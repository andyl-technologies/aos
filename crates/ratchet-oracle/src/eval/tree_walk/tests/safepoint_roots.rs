//! Tree-walk safepoint root-set tests.

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

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn static_gc_address(address_bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(address_bits).expect("static address is a valid GC address")
}

fn relocated_value(tag: ValueTag, address: GcHeapAddress) -> Value {
    Value::heap(
        tag,
        NonNull::new(address.address_bits() as *mut HeapObject)
            .expect("relocated heap address is non-null"),
    )
    .expect("relocated heap value rebuilds")
}

fn test_lambda_record() -> EvalLambda {
    EvalLambda::new(
        IrId::new(0),
        IrId::new(0),
        FrameId::new(0),
        EvalEnv::default(),
    )
}

fn resolved_heap_destination_address(value: ResolvedValueGeneration) -> Option<GcHeapAddress> {
    let ResolvedValueGeneration::Heap { address, .. } = value else {
        return None;
    };

    Some(address)
}

fn has_forwarding_destination(heap: &EvalHeap, destination: Value) -> bool {
    let destination_address = gc_address(destination);
    heap.test_record_values().any(|record| {
        let source = record.expect("heap record value rebuilds");
        if source.raw_eq(destination) {
            return false;
        }
        matches!(
            heap.minor_gc_forwarding_value_at(gc_address(source)),
            Ok(Some(forwarded))
                if resolved_heap_destination_address(forwarded) == Some(destination_address)
        )
    })
}

fn remembered_set_with_only_edge(source: &RememberedSet, edge: RememberedEdge) -> RememberedSet {
    let mut remembered_set = RememberedSet::with_epoch(source.epoch());
    remembered_set
        .record(edge)
        .expect("single remembered edge records");
    remembered_set
}

fn retain_only_thunk_resolve_edge(outcome: &mut EvalOutcome, thunk_value: Value) -> RememberedEdge {
    let retained_edge = RememberedEdge::new(gc_address(thunk_value), gc_address(outcome.value()));
    assert!(
        outcome
            .thunk_resolve_remembered_set()
            .edges()
            .contains(&retained_edge)
    );
    outcome.thunk_resolve_remembered_set =
        remembered_set_with_only_edge(outcome.thunk_resolve_remembered_set(), retained_edge);
    outcome.thunk_resolve_card_table = GcCardTable::default();
    outcome
        .thunk_resolve_card_table
        .mark_source(retained_edge.source())
        .expect("retained edge source card marks");
    retained_edge
}

fn next_dirty_card_source(card_table: &GcCardTable) -> GcHeapAddress {
    let next_index = card_table
        .dirty_cards()
        .iter()
        .map(|card| card.index())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    static_gc_address(next_index.saturating_mul(card_table.card_size_bytes()))
}

fn boundary_remembered_edge_outcome() -> (EvalOutcome, Value) {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark source thunk permanent");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(forced)
        .expect("forced value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    (
        EvalOutcome {
            value: forced,
            heap: evaluator.heap,
            stats,
            attr_telemetry: evaluator.attr_telemetry,
            trace_output: evaluator.trace_output,
            warning_output: evaluator.warning_output,
            impure_input_trace: evaluator.impure_input_trace,
            impure_input_trace_complete: evaluator.impure_input_trace_complete,
            persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
            derivations,
            thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
            thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
            memory_budget_action: None,
            tier_b_transition_admission_report: None,
            cheap_memory_budget_plan: None,
            cheap_memory_advice_report: None,
            cold_hash_consed_value_materialization: None,
            gc_stress_boundary_scans,
            gc_stress_boundary_minor_gc_reference_writebacks:
                EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
            gc_stress_boundary_minor_gc_forwarding_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
            gc_stress_boundary_minor_gc_destination_storage:
                EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
            gc_stress_boundary_minor_gc_object_generations:
                EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
            gc_stress_boundary_minor_gc_writeback_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
        },
        thunk_value,
    )
}

fn boundary_lambda_outcome_with_existing_destination() -> (EvalOutcome, Value, Value) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let original = evaluator.eval_root().expect("lambda evaluates");
    let destination = evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("test destination lambda allocates");

    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(original)
        .expect("lambda value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    (
        EvalOutcome {
            value: original,
            heap: evaluator.heap,
            stats,
            attr_telemetry: evaluator.attr_telemetry,
            trace_output: evaluator.trace_output,
            warning_output: evaluator.warning_output,
            impure_input_trace: evaluator.impure_input_trace,
            impure_input_trace_complete: evaluator.impure_input_trace_complete,
            persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
            derivations,
            thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
            thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
            memory_budget_action: None,
            tier_b_transition_admission_report: None,
            cheap_memory_budget_plan: None,
            cheap_memory_advice_report: None,
            cold_hash_consed_value_materialization: None,
            gc_stress_boundary_scans,
            gc_stress_boundary_minor_gc_reference_writebacks:
                EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
            gc_stress_boundary_minor_gc_forwarding_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
            gc_stress_boundary_minor_gc_destination_storage:
                EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
            gc_stress_boundary_minor_gc_object_generations:
                EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
            gc_stress_boundary_minor_gc_writeback_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
        },
        original,
        destination,
    )
}

fn boundary_permanent_list_field_outcome_with_existing_destination()
-> (EvalOutcome, Value, Value, Value) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let parent = evaluator
        .heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    evaluator
        .thunk_resolve_card_table
        .mark_source(gc_address(parent))
        .expect("permanent parent card marks");
    let destination = evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("test destination lambda allocates");

    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(parent)
        .expect("permanent parent builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    (
        EvalOutcome {
            value: parent,
            heap: evaluator.heap,
            stats,
            attr_telemetry: evaluator.attr_telemetry,
            trace_output: evaluator.trace_output,
            warning_output: evaluator.warning_output,
            impure_input_trace: evaluator.impure_input_trace,
            impure_input_trace_complete: evaluator.impure_input_trace_complete,
            persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
            derivations,
            thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
            thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
            memory_budget_action: None,
            tier_b_transition_admission_report: None,
            cheap_memory_budget_plan: None,
            cheap_memory_advice_report: None,
            cold_hash_consed_value_materialization: None,
            gc_stress_boundary_scans,
            gc_stress_boundary_minor_gc_reference_writebacks:
                EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
            gc_stress_boundary_minor_gc_forwarding_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
            gc_stress_boundary_minor_gc_destination_storage:
                EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
            gc_stress_boundary_minor_gc_object_generations:
                EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
            gc_stress_boundary_minor_gc_writeback_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
        },
        parent,
        child,
        destination,
    )
}

fn boundary_root_and_permanent_lambda_field_outcome_with_existing_destination()
-> (EvalOutcome, Value, Value, Value) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let with_env =
        EvalWithEnv::capture(&[EvalWithScope::new(EvalModuleId::ROOT, IrId::new(8), child)])
            .expect("dynamic with env captures child");
    let parent = evaluator
        .heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
            with_env,
            EvalScopedGlobalEnv::default(),
        ))
        .expect("parent lambda allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    evaluator
        .thunk_resolve_card_table
        .mark_source(gc_address(parent))
        .expect("permanent parent card marks");
    let destination = evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("test destination lambda allocates");
    let frame = EvalFrame::new(1).expect("active frame allocates");
    frame.set(0, parent).expect("active parent root sets");
    evaluator.env.push(frame);

    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(child)
        .expect("child value plus permanent parent builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    (
        EvalOutcome {
            value: child,
            heap: evaluator.heap,
            stats,
            attr_telemetry: evaluator.attr_telemetry,
            trace_output: evaluator.trace_output,
            warning_output: evaluator.warning_output,
            impure_input_trace: evaluator.impure_input_trace,
            impure_input_trace_complete: evaluator.impure_input_trace_complete,
            persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
            derivations,
            thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
            thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
            memory_budget_action: None,
            tier_b_transition_admission_report: None,
            cheap_memory_budget_plan: None,
            cheap_memory_advice_report: None,
            cold_hash_consed_value_materialization: None,
            gc_stress_boundary_scans,
            gc_stress_boundary_minor_gc_reference_writebacks:
                EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
            gc_stress_boundary_minor_gc_forwarding_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
            gc_stress_boundary_minor_gc_destination_storage:
                EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
            gc_stress_boundary_minor_gc_object_generations:
                EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
            gc_stress_boundary_minor_gc_writeback_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
        },
        parent,
        child,
        destination,
    )
}

fn boundary_distinct_root_and_permanent_lambda_field_outcome() -> (EvalOutcome, Value, Value, Value)
{
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let root_child = evaluator.eval_root().expect("root lambda evaluates");
    let field_child = evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("field child lambda allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(8),
        field_child,
    )])
    .expect("dynamic with env captures field child");
    let parent = evaluator
        .heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
            with_env,
            EvalScopedGlobalEnv::default(),
        ))
        .expect("parent lambda allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    evaluator
        .thunk_resolve_card_table
        .mark_source(gc_address(parent))
        .expect("permanent parent card marks");
    let frame = EvalFrame::new(1).expect("active frame allocates");
    frame.set(0, parent).expect("active parent root sets");
    evaluator.env.push(frame);

    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(root_child)
        .expect("root child plus permanent parent builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    (
        EvalOutcome {
            value: root_child,
            heap: evaluator.heap,
            stats,
            attr_telemetry: evaluator.attr_telemetry,
            trace_output: evaluator.trace_output,
            warning_output: evaluator.warning_output,
            impure_input_trace: evaluator.impure_input_trace,
            impure_input_trace_complete: evaluator.impure_input_trace_complete,
            persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
            derivations,
            thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
            thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
            memory_budget_action: None,
            tier_b_transition_admission_report: None,
            cheap_memory_budget_plan: None,
            cheap_memory_advice_report: None,
            cold_hash_consed_value_materialization: None,
            gc_stress_boundary_scans,
            gc_stress_boundary_minor_gc_reference_writebacks:
                EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
            gc_stress_boundary_minor_gc_forwarding_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
            gc_stress_boundary_minor_gc_destination_storage:
                EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
            gc_stress_boundary_minor_gc_object_generations:
                EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
            gc_stress_boundary_minor_gc_writeback_destination_bindings:
                EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
        },
        parent,
        root_child,
        field_child,
    )
}

fn scan_has_value_stack_root(scan: &AllocationCollectorPollScan, value: Value) -> bool {
    scan.scan().roots().iter().any(|scan_root| {
        scan_root.source() == &EvalRootSource::ValueStack { slot: 0 }
            && scan_root.value().raw_eq(value)
    })
}

fn scan_has_object(scan: &AllocationCollectorPollScan, value: Value) -> bool {
    scan.scan()
        .objects()
        .iter()
        .any(|object| object.value().raw_eq(value))
}

fn tree_walk_with_supported_mutable_roots() -> (TreeWalk, Value, Vec<Value>) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let live = evaluator.eval_root().expect("lambda evaluates");

    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, live).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, live));
    evaluator.scoped_globals.push(live);
    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), live)
        .expect("force root pushes");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[EvalPrimOpArg::new(ir.root, Span::new(0, 0), live)],
        )
        .expect("primop root pushes");

    let suspended_frame = EvalFrame::new(1).expect("suspended frame allocates");
    suspended_frame
        .set(0, live)
        .expect("suspended frame slot sets");
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_frame],
        vec![EvalWithScope::new(EvalModuleId::ROOT, ir.root, live)],
        vec![live],
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-import.nix"),
        ImportCacheEntry::Ready {
            value: live,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );

    (evaluator, live, vec![live])
}

fn alloc_test_lambda(evaluator: &mut TreeWalk, id: u32) -> Value {
    evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(id),
            IrId::new(id),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("test lambda allocates")
}

fn tree_walk_with_indexed_mutable_roots() -> (TreeWalk, Vec<Value>) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let active_frame_outer = evaluator.eval_root().expect("root lambda evaluates");
    let active_frame_inner = alloc_test_lambda(&mut evaluator, 1);
    let with_outer = alloc_test_lambda(&mut evaluator, 2);
    let with_inner = alloc_test_lambda(&mut evaluator, 3);
    let scoped_outer = alloc_test_lambda(&mut evaluator, 4);
    let scoped_inner = alloc_test_lambda(&mut evaluator, 5);
    let suspended_outer_frame = alloc_test_lambda(&mut evaluator, 6);
    let suspended_outer_with = alloc_test_lambda(&mut evaluator, 7);
    let suspended_outer_scoped = alloc_test_lambda(&mut evaluator, 8);
    let suspended_inner_frame = alloc_test_lambda(&mut evaluator, 9);
    let suspended_inner_with = alloc_test_lambda(&mut evaluator, 10);
    let suspended_inner_scoped = alloc_test_lambda(&mut evaluator, 11);
    let force_outer = alloc_test_lambda(&mut evaluator, 12);
    let force_inner = alloc_test_lambda(&mut evaluator, 13);
    let primop_outer_arg0 = alloc_test_lambda(&mut evaluator, 14);
    let primop_outer_arg1 = alloc_test_lambda(&mut evaluator, 15);
    let primop_inner_arg0 = alloc_test_lambda(&mut evaluator, 16);
    let primop_inner_arg1 = alloc_test_lambda(&mut evaluator, 17);
    let import_first = alloc_test_lambda(&mut evaluator, 18);
    let import_second = alloc_test_lambda(&mut evaluator, 19);
    let value_stack_0 = alloc_test_lambda(&mut evaluator, 20);
    let value_stack_1 = alloc_test_lambda(&mut evaluator, 21);

    let frame_outer = EvalFrame::new(1).expect("outer frame allocates");
    frame_outer
        .set(0, active_frame_outer)
        .expect("outer frame slot sets");
    let frame_inner = EvalFrame::new(1).expect("inner frame allocates");
    frame_inner
        .set(0, active_frame_inner)
        .expect("inner frame slot sets");
    evaluator.env.push(frame_outer);
    evaluator.env.push(frame_inner);

    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, with_outer));
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, with_inner));
    evaluator.scoped_globals.push(scoped_outer);
    evaluator.scoped_globals.push(scoped_inner);

    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), force_outer)
        .expect("outer force root pushes");
    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), force_inner)
        .expect("inner force root pushes");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[
                EvalPrimOpArg::new(ir.root, Span::new(0, 0), primop_outer_arg0),
                EvalPrimOpArg::new(ir.root, Span::new(0, 0), primop_outer_arg1),
            ],
        )
        .expect("outer primop roots push");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[
                EvalPrimOpArg::new(ir.root, Span::new(0, 0), primop_inner_arg0),
                EvalPrimOpArg::new(ir.root, Span::new(0, 0), primop_inner_arg1),
            ],
        )
        .expect("inner primop roots push");

    let suspended_outer_frame_slot = EvalFrame::new(1).expect("outer suspended frame allocates");
    suspended_outer_frame_slot
        .set(0, suspended_outer_frame)
        .expect("outer suspended frame slot sets");
    let suspended_inner_frame_slot = EvalFrame::new(1).expect("inner suspended frame allocates");
    suspended_inner_frame_slot
        .set(0, suspended_inner_frame)
        .expect("inner suspended frame slot sets");
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("outer suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_outer_frame_slot],
        vec![EvalWithScope::new(
            EvalModuleId::ROOT,
            ir.root,
            suspended_outer_with,
        )],
        vec![suspended_outer_scoped],
    );
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("inner suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_inner_frame_slot],
        vec![EvalWithScope::new(
            EvalModuleId::ROOT,
            ir.root,
            suspended_inner_with,
        )],
        vec![suspended_inner_scoped],
    );

    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-00-evaluating.nix"),
        ImportCacheEntry::Evaluating,
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-01-ready.nix"),
        ImportCacheEntry::Ready {
            value: import_first,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-02-evaluating.nix"),
        ImportCacheEntry::Evaluating,
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-03-ready.nix"),
        ImportCacheEntry::Ready {
            value: import_second,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );

    (evaluator, vec![value_stack_0, value_stack_1])
}

fn root_writeback_plan_for_supported_mutable_roots(
    evaluator: &TreeWalk,
    value_stack: &[Value],
    nursery_base: GcHeapAddress,
) -> AllocationCollectorPollRootWritebackPlan {
    root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
        evaluator,
        value_stack,
        &[],
        nursery_base,
    )
}

fn root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
    evaluator: &TreeWalk,
    value_stack: &[Value],
    primop_arguments: &[Value],
    nursery_base: GcHeapAddress,
) -> AllocationCollectorPollRootWritebackPlan {
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let scan = evaluator
        .safepoint_collector_poll_scan_with_primop_arguments(
            poll,
            value_stack.iter().copied(),
            primop_arguments.iter().copied(),
        )
        .expect("collector poll scans supported roots and primop arguments");
    let remembered_set = RememberedSet::new();
    let minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("collector poll minor-GC plan builds");
    let destinations = evaluator
        .heap()
        .plan_collector_poll_minor_gc_relocation_destinations(
            &minor_gc,
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("relocation destinations plan");
    let commit_plan = minor_gc
        .commit_plan(&destinations)
        .expect("minor-GC commit plan builds");
    evaluator
        .heap()
        .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)
        .expect("reference writeback plan builds")
        .root_writebacks()
        .clone()
}

fn tree_walk_with_mixed_root_and_heap_field_writebacks()
-> (TreeWalk, Value, Value, AllocationCollectorPoll, Vec<Value>) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let parent = evaluator
        .heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent parent list allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    evaluator
        .thunk_resolve_remembered_set
        .record(RememberedEdge::new(gc_address(parent), gc_address(child)))
        .expect("remembered edge records");
    evaluator
        .thunk_resolve_card_table
        .mark_source(gc_address(parent))
        .expect("parent dirty card marks");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-mixed-import.nix"),
        ImportCacheEntry::Ready {
            value: child,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );
    let poll = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requested a collector poll");
    (evaluator, child, parent, poll, vec![child])
}

fn tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination() -> (
    TreeWalk,
    Value,
    Value,
    Value,
    AllocationCollectorPoll,
    Vec<Value>,
) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let destination = evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("scratch destination lambda allocates");
    let parent = evaluator
        .heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent parent list allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    evaluator
        .thunk_resolve_remembered_set
        .record(RememberedEdge::new(gc_address(parent), gc_address(child)))
        .expect("remembered edge records");
    evaluator
        .thunk_resolve_card_table
        .mark_source(gc_address(parent))
        .expect("parent dirty card marks");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-writeback-existing-destination-import.nix"),
        ImportCacheEntry::Ready {
            value: child,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );
    let poll = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requested a collector poll");
    (evaluator, child, parent, destination, poll, vec![child])
}

fn assert_supported_mutable_roots_eq(evaluator: &TreeWalk, value_stack: &[Value], expected: Value) {
    assert!(value_stack[0].raw_eq(expected));
    assert_supported_tree_walk_roots_eq(evaluator, expected);
}

fn assert_supported_tree_walk_roots_eq(evaluator: &TreeWalk, expected: Value) {
    assert!(
        evaluator.env[0]
            .get(0)
            .expect("active frame slot exists")
            .raw_eq(expected)
    );
    assert!(evaluator.with_scopes[0].value().raw_eq(expected));
    assert!(evaluator.scoped_globals[0].raw_eq(expected));
    assert!(evaluator.active_force_roots[0].raw_eq(expected));
    assert!(
        evaluator.active_primop_arg_roots[0]
            .value()
            .raw_eq(expected)
    );
    assert!(
        evaluator.suspended_env_roots[0].env[0]
            .get(0)
            .expect("suspended frame slot exists")
            .raw_eq(expected)
    );
    assert!(
        evaluator.suspended_env_roots[0].with_scopes[0]
            .value()
            .raw_eq(expected)
    );
    assert!(evaluator.suspended_env_roots[0].scoped_globals[0].raw_eq(expected));
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert!(value.raw_eq(expected));
}

fn replacement_for_source(
    plan: &AllocationCollectorPollRootWritebackPlan,
    source: EvalRootSource,
) -> Value {
    plan.writebacks()
        .iter()
        .find(|writeback| writeback.source() == &source)
        .unwrap_or_else(|| panic!("missing writeback for {source:?}"))
        .replacement_value()
        .expect("replacement value reconstructs")
}

fn assert_raw_eq(actual: Value, expected: Value) {
    assert!(
        actual.raw_eq(expected),
        "expected tag {:?}/payload {:#x}, got tag {:?}/payload {:#x}",
        expected.tag(),
        expected.payload_bits(),
        actual.tag(),
        actual.payload_bits()
    );
}

#[test]
fn safepoint_roots_include_active_tree_walk_state_and_interned_roots() {
    let ir = lower("null");
    let mut evaluator = TreeWalk::new(&ir);
    let live = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"live-root".to_vec()))
        .expect("string allocates");

    let frame = EvalFrame::new(3).expect("frame allocates");
    frame.set(1, live).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, live));
    evaluator.scoped_globals.push(live);
    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), live)
        .expect("force root pushes");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[EvalPrimOpArg::new(ir.root, Span::new(0, 0), live)],
        )
        .expect("primop roots push");
    let suspended_frame = EvalFrame::new(2).expect("suspended frame allocates");
    suspended_frame
        .set(0, live)
        .expect("suspended frame slot sets");
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_frame],
        vec![EvalWithScope::new(EvalModuleId::ROOT, ir.root, live)],
        vec![live],
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-import.nix"),
        ImportCacheEntry::Ready {
            value: live,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );

    let roots = evaluator
        .safepoint_root_set()
        .expect("safepoint roots build");
    let sources: Vec<_> = roots.roots().iter().map(EvalRoot::source).collect();

    assert!(sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 1 }));
    assert!(sources.contains(&&EvalRootSource::WithScope { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ScopedGlobal { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ForceContinuation { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::TreeWalkPrimopArgument {
        call_depth: 0,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedTreeWalkFrame {
        depth: 0,
        frame: 0,
        slot: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedWithScope {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedScopedGlobal {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 0,
    }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 2 }));

    let scan = evaluator
        .safepoint_heap_scan()
        .expect("safepoint heap scans");
    assert!(scan.roots().iter().any(|root| root.value().raw_eq(live)));
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(live))
    );
}

#[test]
fn root_value_writebacks_update_supported_tree_walk_roots() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let sources: Vec<_> = plan
        .writebacks()
        .iter()
        .map(|write| write.source())
        .collect();

    assert_eq!(plan.len(), 10);
    assert!(sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(sources.contains(&&EvalRootSource::WithScope { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ScopedGlobal { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ForceContinuation { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::TreeWalkPrimopArgument {
        call_depth: 0,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedTreeWalkFrame {
        depth: 0,
        frame: 0,
        slot: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedWithScope {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedScopedGlobal {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);

    let report = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect("supported root writebacks apply to tree-walk roots");

    assert_eq!(report.writebacks(), plan.len());
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        relocated_value(ValueTag::Lambda, nursery_base),
    );
}

#[test]
fn root_value_writebacks_update_caller_owned_primop_arguments() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let mut primop_arguments = vec![live];
    let nursery_base = static_gc_address(0x1000_0000);
    let plan = root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
        &evaluator,
        &value_stack,
        &primop_arguments,
        nursery_base,
    );
    let sources: Vec<_> = plan
        .writebacks()
        .iter()
        .map(|write| write.source())
        .collect();

    assert_eq!(plan.len(), 11);
    assert!(sources.contains(&&EvalRootSource::PrimopArgument { index: 0 }));

    let report = evaluator
        .apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            &plan,
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("root and primop-argument writebacks apply");

    assert_eq!(report.writebacks(), plan.len());
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        replacement_for_source(&plan, EvalRootSource::ValueStack { slot: 0 }),
    );
    assert_raw_eq(
        primop_arguments[0],
        replacement_for_source(&plan, EvalRootSource::PrimopArgument { index: 0 }),
    );
    assert!(!primop_arguments[0].raw_eq(live));
}

#[test]
fn root_value_writebacks_reject_late_frame_borrow_before_partial_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let suspended_frame = evaluator.suspended_env_roots[0].env[0].clone();
    let _held_frame_borrow = suspended_frame
        .borrow_slots_for_test()
        .expect("test holds suspended frame borrow");

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect_err("held later frame borrow rejects before root mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
    );
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn collector_poll_minor_gc_root_writebacks_apply_to_safepoint_roots() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let report = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
        )
        .expect("collector-poll root writebacks apply");

    assert_eq!(report.poll(), poll);
    assert_eq!(report.scanned_roots(), 10);
    assert_eq!(report.scanned_objects(), 1);
    assert_eq!(report.survivors(), 1);
    assert_eq!(report.reference_slots(), 10);
    assert_eq!(report.root_writebacks(), 10);
    assert_eq!(report.heap_field_writebacks(), 0);
    assert_eq!(report.applied_root_writebacks(), 10);
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        relocated_value(ValueTag::Lambda, nursery_base),
    );
    assert!(!value_stack[0].raw_eq(live));
}

#[test]
fn collector_poll_minor_gc_root_writebacks_apply_to_primop_argument_roots() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let mut primop_arguments = vec![live];
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let report = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("collector-poll primop root writebacks apply");

    assert_eq!(report.poll(), poll);
    assert_eq!(report.scanned_roots(), 11);
    assert_eq!(report.scanned_objects(), 1);
    assert_eq!(report.survivors(), 1);
    assert_eq!(report.reference_slots(), 11);
    assert_eq!(report.root_writebacks(), 11);
    assert_eq!(report.heap_field_writebacks(), 0);
    assert_eq!(report.applied_root_writebacks(), 11);
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        relocated_value(ValueTag::Lambda, nursery_base),
    );
    assert_raw_eq(
        primop_arguments[0],
        relocated_value(ValueTag::Lambda, nursery_base),
    );
    assert!(!primop_arguments[0].raw_eq(live));
}

#[test]
fn collector_poll_minor_gc_root_writebacks_reject_stale_poll_before_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let later = alloc_test_lambda(&mut evaluator, 99);
    assert!(!later.raw_eq(live));
    let current = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("later allocation requested a collector poll");

    let err = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &mut value_stack,
        )
        .expect_err("stale poll is rejected");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        },)
    );
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn collector_poll_minor_gc_reference_writeback_plan_rejects_stale_poll_before_mutation() {
    let (mut evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let later = alloc_test_lambda(&mut evaluator, 100);
    assert!(!later.raw_eq(live));
    let current = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("later allocation requested a collector poll");

    let err = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &value_stack,
        )
        .expect_err("stale poll is rejected");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        },)
    );
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn collector_poll_minor_gc_reference_writebacks_apply_to_safepoint_buffers_all_roots() {
    let (evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("collector-poll reference writebacks apply to buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 10);
    assert_eq!(application.scanned_objects(), 1);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 10);
    assert_eq!(application.root_writebacks(), 10);
    assert_eq!(application.heap_field_writebacks(), 0);
    assert_eq!(application.applied_root_writebacks(), 10);
    assert_eq!(application.applied_heap_field_writebacks(), 0);
    assert_eq!(application.applied_writebacks(), 10);
    assert_eq!(application.report().root_writebacks(), 10);
    assert_eq!(application.root_value_writeback_slots().len(), 10);
    assert!(application.heap_field_writeback_slots().is_empty());
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn reference_writeback_plan_and_buffers_include_caller_owned_primop_arguments() {
    let (evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let primop_arguments = vec![live];
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let bases = MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000));
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            bases,
            &value_stack,
            &primop_arguments,
        )
        .expect("collector-poll reference writeback plan includes primop arguments");

    assert_eq!(plan.scanned_roots(), 11);
    assert_eq!(plan.scanned_objects(), 1);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 11);
    assert_eq!(plan.root_writebacks(), 11);
    assert_eq!(plan.heap_field_writebacks(), 0);
    let root_sources: Vec<_> = plan
        .writebacks()
        .root_writebacks()
        .writebacks()
        .iter()
        .map(|writeback| writeback.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::PrimopArgument { index: 0 }));

    let application = evaluator
        .apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            &plan,
            &value_stack,
            &primop_arguments,
        )
        .expect("reference writebacks apply to primop argument buffers");
    let derived_application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            bases,
            &value_stack,
            &primop_arguments,
        )
        .expect("poll-derived reference writebacks apply to primop argument buffers");

    assert_eq!(application, derived_application);
    assert_eq!(application.applied_root_writebacks(), 11);
    assert_eq!(application.applied_heap_field_writebacks(), 0);
    assert_eq!(application.root_value_writeback_slots().len(), 11);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
    assert_raw_eq(primop_arguments[0], live);
}

#[test]
fn collector_poll_minor_gc_reference_writebacks_reject_stale_poll_before_buffers() {
    let (mut evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let later = alloc_test_lambda(&mut evaluator, 101);
    assert!(!later.raw_eq(live));
    let current = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("later allocation requested a collector poll");

    let err = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &value_stack,
        )
        .expect_err("stale poll is rejected before buffer application");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        },)
    );
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn reference_writebacks_to_safepoint_buffers_reject_stale_root_slot() {
    let (evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &value_stack,
        )
        .expect("reference writeback plan derives");
    let stale = Value::int(99);
    evaluator.env[0]
        .set(0, stale)
        .expect("active frame slot can be made stale");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_buffers(&plan, &value_stack)
        .expect_err("stale typed root slot rejects buffer application");

    let TreeWalkSafepointRootWritebackError::Heap(
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch { actual_tag, .. },
    ) = err
    else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(actual_tag, ValueTag::Int);
    assert_raw_eq(value_stack[0], live);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        stale,
    );
}

#[test]
fn typed_reference_writeback_plan_rejects_stale_heap_field_before_root_buffer_mutation() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (evaluator, child, _parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");
    let root_plan = plan.writebacks().root_writebacks();
    let heap_plan = plan.writebacks().heap_field_writebacks();
    let mut root_slots: Vec<_> = root_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollRootValueWritebackSlot::new(
                writeback.source().clone(),
                writeback
                    .expected_value()
                    .expect("expected root reconstructs"),
            )
        })
        .collect();
    let mut heap_slots: Vec<_> = heap_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollHeapFieldWritebackSlot::new(
                writeback.validation_object(),
                writeback.writeback_object(),
                writeback.field_index(),
                writeback.source().clone(),
                ResolvedValueGeneration::Inline,
            )
        })
        .collect();

    let err = plan
        .writebacks()
        .apply_to_value_and_heap_field_slots(&mut root_slots, &mut heap_slots)
        .expect_err("stale heap-field metadata rejects typed combined application");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 4,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    for slot in &root_slots {
        assert_raw_eq(slot.value(), child);
    }
    assert_eq!(heap_slots[0].value(), ResolvedValueGeneration::Inline);
}

#[test]
fn reference_writebacks_to_safepoint_buffers_reject_stale_live_heap_field() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");
    evaluator
        .heap
        .set_allocation_domain_for_test(child, HeapAllocationDomain::PermanentShared)
        .expect("test can stale the live field generation");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_buffers(&plan, &value_stack)
        .expect_err("stale live heap-field slot rejects buffer application");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: 4,
                expected: ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
                actual: ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Permanent,
                },
            },
        )
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

#[test]
fn collector_poll_minor_gc_reference_writeback_plan_reports_mixed_partitions() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_epoch = evaluator.thunk_resolve_remembered_set().epoch();
    let next_epoch = source_epoch
        .checked_next()
        .expect("remembered-set epoch advances");
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");

    assert_eq!(plan.poll(), poll);
    assert_eq!(plan.scanned_roots(), 4);
    assert_eq!(plan.scanned_objects(), 2);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 5);
    assert_eq!(plan.destination_placements(), 1);
    assert_eq!(
        plan.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        plan.nursery_reserved_bytes(),
        plan.object_body_plan().requests()[0].size_bytes()
    );
    assert_eq!(plan.old_reserved_bytes(), 0);
    assert_eq!(plan.total_reserved_bytes(), plan.nursery_reserved_bytes());
    assert_eq!(plan.source_remembered_set().epoch(), source_epoch);
    assert_eq!(plan.source_remembered_set_edges(), 1);
    assert_eq!(
        plan.source_remembered_set().edges(),
        &[RememberedEdge::new(gc_address(parent), gc_address(child))]
    );
    assert_eq!(plan.source_dirty_cards(), 1);
    assert!(
        plan.source_card_table()
            .snapshot()
            .covers_source(gc_address(parent))
    );
    assert_eq!(plan.remembered_set_refreshes(), 1);
    assert_eq!(plan.next_remembered_set().epoch(), next_epoch);
    assert_eq!(plan.next_remembered_set_edges(), 1);
    assert_eq!(
        plan.next_remembered_set().edges(),
        &[RememberedEdge::new(gc_address(parent), nursery_base)]
    );
    assert_eq!(plan.writebacks().len(), 4);
    assert_eq!(plan.root_writebacks(), 3);
    assert_eq!(plan.heap_field_writebacks(), 1);
    let root_sources: Vec<_> = plan
        .writebacks()
        .root_writebacks()
        .writebacks()
        .iter()
        .map(|writeback| writeback.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    let heap_field_writebacks = plan.writebacks().heap_field_writebacks().writebacks();
    assert_eq!(heap_field_writebacks.len(), 1);
    let heap_writeback = &heap_field_writebacks[0];
    assert_eq!(heap_writeback.slot(), 4);
    assert_eq!(heap_writeback.validation_object(), gc_address(parent));
    assert_eq!(heap_writeback.writeback_object(), gc_address(parent));
    assert_eq!(heap_writeback.field_index(), 0);
    assert_eq!(
        heap_writeback.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_writeback.expected(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap_writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_raw_eq(value_stack[0], child);
}

#[test]
fn collector_poll_minor_gc_reference_writebacks_apply_to_safepoint_buffers_mixed_partitions() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writebacks apply to buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 4);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 5);
    assert_eq!(application.root_writebacks(), 3);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.applied_heap_field_writebacks(), 1);
    assert_eq!(application.applied_writebacks(), 4);
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    let root_sources: Vec<_> = application
        .root_value_writeback_slots()
        .iter()
        .map(|slot| slot.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }

    let heap_field_slots = application.heap_field_writeback_slots();
    assert_eq!(heap_field_slots.len(), 1);
    let heap_slot = &heap_field_slots[0];
    assert_eq!(heap_slot.validation_object(), gc_address(parent));
    assert_eq!(heap_slot.writeback_object(), gc_address(parent));
    assert_eq!(heap_slot.field_index(), 0);
    assert_eq!(
        heap_slot.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_slot.value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

#[test]
fn reference_writebacks_apply_root_storage_after_field_buffer_validation() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
        )
        .expect("mixed reference writebacks apply to roots and field buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 4);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 5);
    assert_eq!(application.root_writebacks(), 3);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.applied_heap_field_writebacks(), 1);
    assert_eq!(application.applied_writebacks(), 4);
    assert_eq!(application.buffers().applied_writebacks(), 4);
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }

    let heap_field_slots = application.heap_field_writeback_slots();
    assert_eq!(heap_field_slots.len(), 1);
    assert_eq!(heap_field_slots[0].validation_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].writeback_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].field_index(), 0);
    assert_eq!(
        heap_field_slots[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_field_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

#[test]
fn reference_writebacks_apply_root_storage_and_field_buffers_with_primop_arguments() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let mut primop_arguments = vec![child];
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("mixed primop reference writebacks apply to roots and field buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 5);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 6);
    assert_eq!(application.root_writebacks(), 4);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.applied_heap_field_writebacks(), 1);
    assert_eq!(application.applied_writebacks(), 5);
    assert_eq!(application.buffers().applied_writebacks(), 5);
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    let root_sources: Vec<_> = application
        .root_value_writeback_slots()
        .iter()
        .map(|slot| slot.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::PrimopArgument { index: 0 }));
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }

    let heap_field_slots = application.heap_field_writeback_slots();
    assert_eq!(heap_field_slots.len(), 1);
    assert_eq!(heap_field_slots[0].validation_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].writeback_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].field_index(), 0);
    assert_eq!(
        heap_field_slots[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_field_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

#[test]
fn reference_writebacks_root_storage_reject_late_frame_borrow_before_partial_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("reference writeback plan derives for supported roots");
    let suspended_frame = evaluator.suspended_env_roots[0].env[0].clone();
    let _held_frame_borrow = suspended_frame
        .borrow_slots_for_test()
        .expect("test holds suspended frame borrow");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            &plan,
            &mut value_stack,
        )
        .expect_err("held later frame borrow rejects before root mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
    );
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn reference_writebacks_validate_existing_destination_without_mutation() {
    let (evaluator, child, parent, destination, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    assert_eq!(plan.object_bodies(), 1);
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), gc_address(child));
    assert_eq!(request.destination(), destination_address);

    let preflight = evaluator
        .validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            &plan,
            &value_stack,
        )
        .expect("mixed reference writebacks validate without mutation");
    let derived_preflight = evaluator
        .validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("poll-derived mixed reference writebacks validate without mutation");
    assert_eq!(derived_preflight, preflight);

    assert_eq!(preflight.poll(), poll);
    assert_eq!(preflight.scanned_roots(), 4);
    assert_eq!(preflight.scanned_objects(), 2);
    assert_eq!(preflight.survivors(), 1);
    assert_eq!(preflight.reference_slots(), 5);
    assert_eq!(preflight.root_writebacks(), 3);
    assert_eq!(preflight.heap_field_writebacks(), 1);
    assert_eq!(preflight.object_bodies_preflighted(), 1);
    assert_eq!(preflight.object_generations_preflighted(), 1);
    assert_eq!(preflight.validated_root_writebacks(), 3);
    assert_eq!(preflight.live_heap_field_writebacks(), 1);
    assert_eq!(preflight.validated_live_writebacks(), 4);
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in preflight.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_eq!(preflight.heap_field_writeback_slots().len(), 1);
    assert_eq!(
        resolved_heap_destination_address(preflight.heap_field_writeback_slots()[0].value()),
        Some(destination_address)
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_apply_root_storage_and_live_heap_fields_for_existing_destination() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    assert_eq!(plan.object_bodies(), 1);
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), gc_address(child));
    assert_eq!(request.destination(), destination_address);

    let application = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect("mixed reference writebacks apply to roots and live heap fields");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 4);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 5);
    assert_eq!(application.root_writebacks(), 3);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    assert_eq!(application.remembered_set_published_edges(), 1);
    assert_eq!(application.card_table_clear_report().dirty_cards(), 1);
    assert_eq!(application.card_table_dirty_cards_cleared(), 1);
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    evaluator
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda)
        .expect("existing destination body is bound");
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    let expected_edges = [RememberedEdge::new(gc_address(parent), destination_address)];
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        expected_edges.as_slice()
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_validate_and_apply_live_heap_fields_with_primop_arguments() {
    {
        let (evaluator, child, parent, destination, poll, value_stack) =
            tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
        let destination_address = gc_address(destination);
        let primop_arguments = vec![child];
        let preflight = evaluator
            .validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
                poll,
                MinorGcPromotionPolicy::new(2),
                MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
                &value_stack,
                &primop_arguments,
            )
            .expect("mixed primop reference writebacks validate without mutation");

        assert_eq!(preflight.poll(), poll);
        assert_eq!(preflight.scanned_roots(), 5);
        assert_eq!(preflight.scanned_objects(), 2);
        assert_eq!(preflight.survivors(), 1);
        assert_eq!(preflight.reference_slots(), 6);
        assert_eq!(preflight.root_writebacks(), 4);
        assert_eq!(preflight.heap_field_writebacks(), 1);
        assert_eq!(preflight.object_bodies_preflighted(), 1);
        assert_eq!(preflight.object_generations_preflighted(), 1);
        assert_eq!(preflight.validated_root_writebacks(), 4);
        assert_eq!(preflight.live_heap_field_writebacks(), 1);
        assert_eq!(preflight.validated_live_writebacks(), 5);
        assert!(
            preflight
                .root_value_writeback_slots()
                .iter()
                .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
        );
        let relocated = relocated_value(ValueTag::Lambda, destination_address);
        for slot in preflight.root_value_writeback_slots() {
            assert_raw_eq(slot.value(), relocated);
        }
        assert_eq!(preflight.heap_field_writeback_slots().len(), 1);
        assert_eq!(
            resolved_heap_destination_address(preflight.heap_field_writeback_slots()[0].value()),
            Some(destination_address)
        );
        assert_raw_eq(value_stack[0], child);
        assert_raw_eq(primop_arguments[0], child);
        assert_raw_eq(
            evaluator
                .heap()
                .get_list(parent)
                .expect("parent list remains typed")
                .get(0)
                .expect("parent list element exists"),
            child,
        );
    }

    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let mut primop_arguments = vec![child];
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("mixed primop reference writebacks apply to roots and live heap fields");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 5);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 6);
    assert_eq!(application.root_writebacks(), 4);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    assert_eq!(application.remembered_set_published_edges(), 1);
    assert_eq!(application.card_table_dirty_cards_cleared(), 1);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    let expected_edges = [RememberedEdge::new(gc_address(parent), destination_address)];
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        expected_edges.as_slice()
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_reserved_destination_rejects_stale_worker_poll_before_reservation() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let stale_poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a worker collector poll");
    let sibling = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("sibling thunk allocation advances worker poll");
    let current_poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("sibling allocation requested a worker collector poll");
    let records_before = evaluator.heap().len();
    let worker_safepoints_before = evaluator.heap().allocation_safepoints();
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints();
    let value_stack = vec![child, sibling];

    let err = evaluator
        .validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            stale_poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect_err("stale worker poll rejects before destination reservation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll: stale_poll,
            current: Some(current_poll),
        },)
    );
    assert_eq!(evaluator.heap().len(), records_before);
    assert_eq!(
        evaluator.heap().allocation_safepoints(),
        worker_safepoints_before
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints(),
        permanent_safepoints_before
    );
}

#[test]
fn reference_writebacks_apply_reserved_worker_poll_switch_and_promote_destination() {
    let ir = lower("let keep = 1; in x: keep");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a worker collector poll");
    assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
    let records_before = evaluator.heap().len();
    let mut value_stack = vec![child];

    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(0),
            &mut value_stack,
        )
        .expect("reserved worker-poll writebacks apply");

    assert_ne!(application.poll(), poll);
    assert_eq!(
        application.poll().tier(),
        RuntimeAllocatorTier::TierAOneShot
    );
    assert_eq!(
        evaluator
            .heap()
            .allocation_safepoints()
            .last_safepoint_collector_poll(),
        Some(application.poll())
    );
    assert_eq!(evaluator.heap().len(), records_before + 1);
    assert_eq!(application.scanned_roots(), 1);
    assert_eq!(application.scanned_objects(), 1);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 1);
    assert_eq!(application.root_writebacks(), 1);
    assert_eq!(application.heap_field_writebacks(), 0);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 1);
    assert_eq!(application.live_heap_field_writebacks(), 0);
    assert_eq!(application.applied_live_writebacks(), 1);
    assert_eq!(application.remembered_set_published_edges(), 0);
    assert_eq!(application.card_table_dirty_cards_cleared(), 0);
    assert_ne!(gc_address(value_stack[0]), gc_address(child));
    assert_eq!(
        evaluator
            .heap()
            .generation(value_stack[0])
            .expect("promoted reserved destination is heap-bound"),
        HeapGeneration::Old
    );
}

#[test]
fn reference_writebacks_reserved_destination_plan_reports_promoted_placement_bytes() {
    let ir = lower("let keep = 1; in x: keep");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let child_address = gc_address(child);
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a worker collector poll");
    let records_before = evaluator.heap().len();
    let value_stack = vec![child];

    let plan = evaluator
        .collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(0),
            &value_stack,
        )
        .expect("reserved promoted destination reference writeback plan derives");

    assert_ne!(plan.poll(), poll);
    assert_eq!(evaluator.heap().len(), records_before + 1);
    assert_eq!(plan.scanned_roots(), 1);
    assert_eq!(plan.scanned_objects(), 1);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 1);
    assert_eq!(plan.destination_placements(), 1);
    assert_eq!(
        plan.placement_plan().placements()[0].source(),
        child_address
    );
    assert_eq!(
        plan.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(plan.nursery_reserved_bytes(), 0);
    assert_eq!(
        plan.old_reserved_bytes(),
        plan.object_body_plan().requests()[0].size_bytes()
    );
    assert_eq!(plan.total_reserved_bytes(), plan.old_reserved_bytes());
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), child_address);
    assert_eq!(request.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(request.destination_generation(), HeapGeneration::Old);
}

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

#[test]
fn reference_writebacks_reserved_destination_apply_accepts_periodic_poll_without_reservation_poll()
{
    let (mut evaluator, poll, mut value_stack) =
        tree_walk_with_periodic_poll_before_single_young_reservation();
    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("reserved bridge applies when reservation itself does not poll");

    assert_periodic_poll_reserved_application_without_reservation_poll(
        &evaluator,
        value_stack[0],
        application.applied_root_writebacks(),
    );
}

#[test]
fn reference_writebacks_reserved_forwarding_apply_accepts_periodic_poll_without_reservation_poll() {
    let (mut evaluator, poll, mut value_stack) =
        tree_walk_with_periodic_poll_before_single_young_reservation();
    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("reserved bridge applies when reservation itself does not poll");

    assert_periodic_poll_reserved_application_without_reservation_poll(
        &evaluator,
        value_stack[0],
        application.applied_root_writebacks(),
    );
}

#[test]
fn reference_writebacks_validate_reserved_destination_without_live_mutation() {
    let (mut evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let child_address = gc_address(child);
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let preflight = evaluator
        .validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect("reserved destination reference writebacks validate without live mutation");

    assert_eq!(preflight.poll(), poll);
    assert_eq!(preflight.scanned_roots(), 4);
    assert_eq!(preflight.scanned_objects(), 2);
    assert_eq!(preflight.survivors(), 1);
    assert_eq!(preflight.reference_slots(), 5);
    assert_eq!(preflight.root_writebacks(), 3);
    assert_eq!(preflight.heap_field_writebacks(), 1);
    assert_eq!(preflight.object_bodies_preflighted(), 1);
    assert_eq!(preflight.object_generations_preflighted(), 1);
    assert_eq!(preflight.validated_root_writebacks(), 3);
    assert_eq!(preflight.live_heap_field_writebacks(), 1);
    assert_eq!(preflight.validated_live_writebacks(), 4);
    let destination_address = gc_address(preflight.root_value_writeback_slots()[0].value());
    assert_ne!(destination_address, child_address);
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in preflight.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_eq!(preflight.heap_field_writeback_slots().len(), 1);
    assert_eq!(
        resolved_heap_destination_address(preflight.heap_field_writeback_slots()[0].value()),
        Some(destination_address)
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(relocated)
            .expect("reserved destination is heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_reserved_destination_plan_uses_unbound_placeholder_body() {
    let (mut evaluator, child, _parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let child_address = gc_address(child);
    let plan = evaluator
        .collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect("reserved destination reference writeback plan derives");

    assert_eq!(plan.poll(), poll);
    assert_eq!(plan.scanned_roots(), 4);
    assert_eq!(plan.scanned_objects(), 2);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 5);
    assert_eq!(plan.destination_placements(), 1);
    assert_eq!(
        plan.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        plan.nursery_reserved_bytes(),
        plan.object_body_plan().requests()[0].size_bytes()
    );
    assert_eq!(plan.old_reserved_bytes(), 0);
    assert_eq!(plan.total_reserved_bytes(), plan.nursery_reserved_bytes());
    assert_eq!(plan.object_bodies(), 1);
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), child_address);
    assert_ne!(request.destination(), child_address);
    assert_eq!(request.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(request.destination_generation(), HeapGeneration::Young);
    assert!(matches!(
        evaluator
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let preflight = evaluator
        .validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            &plan,
            &value_stack,
        )
        .expect("reserved destination plan preflights");
    assert_eq!(preflight.object_bodies_preflighted(), 1);
    assert!(matches!(
        evaluator
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

#[test]
fn reference_writebacks_apply_reserved_destination_with_primop_arguments() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let child_address = gc_address(child);
    let mut primop_arguments = vec![child];
    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("reserved destination writebacks apply to roots and live heap fields");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 5);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 6);
    assert_eq!(application.root_writebacks(), 4);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    assert_eq!(application.remembered_set_published_edges(), 1);
    assert_eq!(application.card_table_clear_report().dirty_cards(), 1);
    assert_eq!(application.card_table_dirty_cards_cleared(), 1);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let destination_address = gc_address(application.root_value_writeback_slots()[0].value());
    assert_ne!(destination_address, child_address);
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(relocated)
            .expect("reserved destination remains heap-bound"),
        HeapGeneration::Young
    );
    let expected_edges = [RememberedEdge::new(gc_address(parent), destination_address)];
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        expected_edges.as_slice()
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_apply_reserved_destination_with_forwarding_slots() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);
    let plan = evaluator
        .collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect("reserved destination reference writeback plan derives");
    assert_eq!(plan.forwarding_pointers(), 1);
    let forwarding_slot = plan.forwarding_slots()[0];
    assert_eq!(forwarding_slot.source(), source_address);
    let forwarded = forwarding_slot
        .forwarded_value()
        .expect("forwarding slot is filled");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    assert_ne!(destination_address, source_address);

    let application = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            &plan,
            &mut value_stack,
        )
        .expect("reserved destination writebacks install forwarding and apply");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    assert_eq!(
        evaluator
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("forwarding source remains known"),
        Some(forwarded)
    );
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_apply_reserved_destination_wrapper_with_forwarding_slots() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);

    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("reserved destination wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_apply_reserved_forwarding_wrapper_with_primop_arguments() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);
    let mut primop_arguments = vec![child];

    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("reserved destination primop wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.root_value_writeback_slots().len(), 4);
    assert_eq!(application.heap_field_writeback_slots().len(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_apply_current_reserved_forwarding_wrapper() {
    let (mut evaluator, child, parent, _poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);

    let application = evaluator
        .apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            RuntimeAllocatorTier::PermanentShared,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("current reserved destination wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_apply_current_reserved_forwarding_wrapper_with_primop_arguments() {
    let (mut evaluator, child, parent, _poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);
    let mut primop_arguments = vec![child];

    let application = evaluator
        .apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            RuntimeAllocatorTier::PermanentShared,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("current reserved destination primop wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.root_value_writeback_slots().len(), 4);
    assert_eq!(application.heap_field_writeback_slots().len(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_current_reserved_forwarding_wrapper_rejects_missing_poll_without_reservation()
 {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::disabled()),
    );
    let records_before = evaluator.heap().len();
    let mut value_stack = Vec::new();

    let err = evaluator
        .apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            RuntimeAllocatorTier::TierAOneShot,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect_err("missing current poll rejects before reservation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(
            TreeWalkSafepointScanError::NoCurrentCollectorPoll {
                tier: RuntimeAllocatorTier::TierAOneShot
            },
        )
    );
    assert_eq!(evaluator.heap().len(), records_before);
}

#[test]
fn reference_writebacks_forwarding_slots_reject_occupied_before_live_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let forwarding_slot = plan.forwarding_slots()[0];
    let forwarded = forwarding_slot
        .forwarded_value()
        .expect("forwarding slot is filled");
    evaluator
        .heap
        .install_collector_poll_minor_gc_forwarding_slots(plan.forwarding_slots())
        .expect("initial forwarding slot installs");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            &plan,
            &mut value_stack,
        )
        .expect_err("occupied forwarding slot rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
                index: 0,
                address: source_address,
                actual: forwarded,
            },
        ))
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_forwarding_slots_reject_frame_borrow_without_forwarding_install() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let active_frame = evaluator.env[0].clone();
    let _held_frame_borrow = active_frame
        .borrow_slots_for_test()
        .expect("test holds active frame borrow");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            &plan,
            &mut value_stack,
        )
        .expect_err("held frame borrow rejects before forwarding install");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
    );
    assert_eq!(
        evaluator
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("forwarding source remains known"),
        None
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_reject_frame_borrow_before_body_or_field_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let active_frame = evaluator.env[0].clone();
    let _held_frame_borrow = active_frame
        .borrow_slots_for_test()
        .expect("test holds active frame borrow");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect_err("held frame borrow rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_reject_stale_source_remembered_set_before_live_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let stale_edge = RememberedEdge::new(
        static_gc_address(0x3000_0000),
        static_gc_address(0x3000_1000),
    );
    evaluator
        .thunk_resolve_remembered_set
        .record(stale_edge)
        .expect("stale remembered edge records");
    let stale_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect_err("stale source remembered set rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::SourceRememberedSetLengthMismatch {
            expected: 1,
            actual: 2,
        }
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        stale_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_reject_stale_source_card_table_before_live_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let extra_card_source = next_dirty_card_source(&evaluator.thunk_resolve_card_table);
    evaluator
        .thunk_resolve_card_table
        .mark_source(extra_card_source)
        .expect("stale card table source marks");
    let stale_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect_err("stale source card table rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::SourceCardTableLengthMismatch {
            expected: 1,
            actual: 2,
        }
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        stale_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_validate_rejects_synthetic_destination_without_mutation() {
    let synthetic_destination = static_gc_address(0x1000_0000);
    let (evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();

    let err = evaluator
        .validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(synthetic_destination, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect_err("synthetic destination rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: synthetic_destination,
            },
        )
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_reject_synthetic_destination_before_root_or_field_mutation() {
    let synthetic_destination = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();

    let err = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(synthetic_destination, static_gc_address(0x2000_0000)),
            &mut value_stack,
        )
        .expect_err("synthetic destination rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: synthetic_destination,
            },
        )
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn reference_writebacks_reject_stale_live_field_before_root_storage_mutation() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");
    evaluator
        .heap
        .set_allocation_domain_for_test(child, HeapAllocationDomain::PermanentShared)
        .expect("test can stale the live field generation");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            &plan,
            &mut value_stack,
        )
        .expect_err("stale live field rejects before tree-walk root mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: 4,
                expected: ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
                actual: ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Permanent,
                },
            },
        )
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

#[test]
fn collector_poll_minor_gc_root_writebacks_reject_heap_field_partition_before_mutation() {
    let (mut evaluator, child, _parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();

    let err = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &mut value_stack,
        )
        .expect_err("root-only helper rejects mixed root/field writebacks");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::UnsupportedHeapFieldWritebacks {
            heap_field_writebacks: 1,
        }
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
}

#[test]
fn root_value_writebacks_preserve_reverse_depth_and_ready_import_indexes() {
    let (mut evaluator, mut value_stack) = tree_walk_with_indexed_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);

    assert_eq!(plan.len(), 22);

    let report = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect("indexed root writebacks apply");

    assert_eq!(report.writebacks(), plan.len());
    assert_raw_eq(
        value_stack[0],
        replacement_for_source(&plan, EvalRootSource::ValueStack { slot: 0 }),
    );
    assert_raw_eq(
        value_stack[1],
        replacement_for_source(&plan, EvalRootSource::ValueStack { slot: 1 }),
    );
    assert_raw_eq(
        evaluator.env[0].get(0).expect("outer frame slot exists"),
        replacement_for_source(&plan, EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }),
    );
    assert_raw_eq(
        evaluator.env[1].get(0).expect("inner frame slot exists"),
        replacement_for_source(&plan, EvalRootSource::TreeWalkFrame { frame: 1, slot: 0 }),
    );
    assert_raw_eq(
        evaluator.with_scopes[0].value(),
        replacement_for_source(&plan, EvalRootSource::WithScope { depth: 0 }),
    );
    assert_raw_eq(
        evaluator.with_scopes[1].value(),
        replacement_for_source(&plan, EvalRootSource::WithScope { depth: 1 }),
    );
    assert_raw_eq(
        evaluator.scoped_globals[0],
        replacement_for_source(&plan, EvalRootSource::ScopedGlobal { depth: 0 }),
    );
    assert_raw_eq(
        evaluator.scoped_globals[1],
        replacement_for_source(&plan, EvalRootSource::ScopedGlobal { depth: 1 }),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[1].env[0]
            .get(0)
            .expect("nearest suspended frame slot exists"),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedTreeWalkFrame {
                depth: 0,
                frame: 0,
                slot: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[0].env[0]
            .get(0)
            .expect("outer suspended frame slot exists"),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedTreeWalkFrame {
                depth: 1,
                frame: 0,
                slot: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[1].with_scopes[0].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedWithScope {
                depth: 0,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[0].with_scopes[0].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedWithScope {
                depth: 1,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[1].scoped_globals[0],
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedScopedGlobal {
                depth: 0,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[0].scoped_globals[0],
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedScopedGlobal {
                depth: 1,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_force_roots[1],
        replacement_for_source(&plan, EvalRootSource::ForceContinuation { depth: 0 }),
    );
    assert_raw_eq(
        evaluator.active_force_roots[0],
        replacement_for_source(&plan, EvalRootSource::ForceContinuation { depth: 1 }),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[2].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 0,
                index: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[3].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 0,
                index: 1,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[0].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 1,
                index: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[1].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 1,
                index: 1,
            },
        ),
    );
    let ImportCacheEntry::Ready {
        value: first_import,
        ..
    } = evaluator
        .import_cache
        .get(&PathBuf::from("/tmp/safepoint-root-writeback-01-ready.nix"))
        .expect("first ready import remains cached")
    else {
        panic!("first import cache entry remains ready");
    };
    assert_raw_eq(
        *first_import,
        replacement_for_source(&plan, EvalRootSource::ImportCache { index: 0 }),
    );
    let ImportCacheEntry::Ready {
        value: second_import,
        ..
    } = evaluator
        .import_cache
        .get(&PathBuf::from("/tmp/safepoint-root-writeback-03-ready.nix"))
        .expect("second ready import remains cached")
    else {
        panic!("second import cache entry remains ready");
    };
    assert_raw_eq(
        *second_import,
        replacement_for_source(&plan, EvalRootSource::ImportCache { index: 1 }),
    );
}

#[test]
fn root_value_writebacks_reject_stale_value_stack_before_tree_walk_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let stale_value = Value::int(1);
    value_stack[0] = stale_value;

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect_err("stale value-stack root rejects before live tree-walk roots mutate");

    assert!(matches!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                actual_tag: ValueTag::Int,
                ..
            }
        )
    ));
    assert!(value_stack[0].raw_eq(stale_value));
    assert_supported_tree_walk_roots_eq(&evaluator, live);
}

#[test]
fn root_value_writebacks_reject_stale_primop_argument_before_tree_walk_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let mut primop_arguments = vec![live];
    let nursery_base = static_gc_address(0x1000_0000);
    let plan = root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
        &evaluator,
        &value_stack,
        &primop_arguments,
        nursery_base,
    );
    let stale_value = Value::int(1);
    primop_arguments[0] = stale_value;

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            &plan,
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect_err("stale primop argument rejects before tree-walk roots mutate");

    assert!(matches!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                actual_tag: ValueTag::Int,
                ..
            }
        )
    ));
    assert!(primop_arguments[0].raw_eq(stale_value));
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

#[test]
fn root_value_writebacks_reject_stale_active_frame_before_any_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let stale_value = Value::int(1);
    evaluator.env[0]
        .set(0, stale_value)
        .expect("test can stale active frame slot");

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect_err("stale active frame rejects before root mutation");

    assert!(matches!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                actual_tag: ValueTag::Int,
                ..
            }
        )
    ));
    assert!(value_stack[0].raw_eq(live));
    assert!(
        evaluator.env[0]
            .get(0)
            .expect("active frame slot remains readable")
            .raw_eq(stale_value)
    );
    assert!(evaluator.with_scopes[0].value().raw_eq(live));
    assert!(evaluator.scoped_globals[0].raw_eq(live));
    assert!(evaluator.active_force_roots[0].raw_eq(live));
    assert!(evaluator.active_primop_arg_roots[0].value().raw_eq(live));
    assert!(
        evaluator.suspended_env_roots[0].env[0]
            .get(0)
            .expect("suspended frame slot remains readable")
            .raw_eq(live)
    );
    assert!(
        evaluator.suspended_env_roots[0].with_scopes[0]
            .value()
            .raw_eq(live)
    );
    assert!(evaluator.suspended_env_roots[0].scoped_globals[0].raw_eq(live));
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert!(value.raw_eq(live));
}

#[test]
fn active_safepoint_roots_are_removed_after_force_and_primop_errors() {
    let recursive = lower("let x = x; in x");
    let mut recursive_eval = TreeWalk::new(&recursive);
    recursive_eval
        .eval_root()
        .expect_err("recursive force reports blackhole");
    let recursive_roots = recursive_eval
        .safepoint_root_set()
        .expect("roots build after force error");
    assert!(recursive_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));

    let bad_primop = lower("let add = builtins.add; in add 1 \"x\"");
    let mut primop_eval = TreeWalk::new(&bad_primop);
    primop_eval
        .eval_root()
        .expect_err("bad first-class primop reports type error");
    let primop_roots = primop_eval
        .safepoint_root_set()
        .expect("roots build after primop error");
    assert!(primop_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::TreeWalkPrimopArgument { .. }
                | EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));
}

#[test]
fn gc_stress_poll_scan_uses_tree_walk_roots_plus_transient_value_stack() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let root = evaluator.eval_root().expect("lambda evaluates");
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");

    assert_eq!(
        poll.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );

    let remembered_set = RememberedSet::new();
    let empty_scan = evaluator
        .safepoint_collector_poll_scan(poll, [])
        .expect("collector poll scan accepts empty transient roots");
    assert!(empty_scan.scan().roots().is_empty());
    let empty_minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &empty_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("empty collector poll scan plans");
    assert!(empty_minor_gc.plan().survivors().is_empty());

    let scan = evaluator
        .safepoint_collector_poll_scan(poll, [root])
        .expect("collector poll roots scan");
    let stack_root = scan
        .scan()
        .roots()
        .iter()
        .find(|scan_root| scan_root.source() == &EvalRootSource::ValueStack { slot: 0 })
        .expect("transient value-stack root records");
    assert!(stack_root.value().raw_eq(root));
    assert!(
        scan.scan()
            .objects()
            .iter()
            .any(|object| { object.value().raw_eq(root) })
    );

    let minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("collector poll minor-GC planning accepts the tree-walk scan");
    assert_eq!(minor_gc.plan().survivors().len(), 1);
    assert_eq!(minor_gc.plan().survivors()[0].address(), gc_address(root));
}

#[test]
fn gc_stress_allocation_safepoint_rewrites_registered_transient_value_stack_root() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let local_source = evaluator
        .heap
        .alloc_lambda(test_lambda_record())
        .expect("registered local lambda allocates");
    let local_source_address = gc_address(local_source);
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let allocated: Value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_tree_walk_thunk(ir.root, span, EvalThunk::new(ir.root))
        })
        .expect("GC-stress allocation rewrites registered transient roots");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert_ne!(gc_address(roots[0]), local_source_address);
    assert_eq!(roots[0].tag(), ValueTag::Lambda);
    assert_eq!(allocated.tag(), ValueTag::Thunk);
    assert!(!allocated.raw_eq(roots[0]));
    assert!(has_forwarding_destination(evaluator.heap(), roots[0]));
    assert!(has_forwarding_destination(evaluator.heap(), allocated));
    assert_eq!(
        evaluator
            .heap()
            .generation(roots[0])
            .expect("registered root destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(allocated)
            .expect("allocated value destination remains heap-bound"),
        HeapGeneration::Young
    );
}

#[test]
fn gc_stress_allocation_safepoint_rewrites_deep_force_visited_roots() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let local_source = evaluator
        .heap
        .alloc_lambda(test_lambda_record())
        .expect("registered local lambda allocates");
    let local_source_address = gc_address(local_source);
    let mut visited = vec![local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let allocated: Value = evaluator
        .with_deep_force_visited_roots(ir.root, span, &mut visited, |eval, _visited| {
            eval.alloc_tree_walk_thunk(ir.root, span, EvalThunk::new(ir.root))
        })
        .expect("GC-stress allocation rewrites deep-force visited roots");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert_ne!(gc_address(visited[0]), local_source_address);
    assert_eq!(visited[0].tag(), ValueTag::Lambda);
    assert_eq!(allocated.tag(), ValueTag::Thunk);
    assert!(!allocated.raw_eq(visited[0]));
    assert!(has_forwarding_destination(evaluator.heap(), visited[0]));
    assert!(has_forwarding_destination(evaluator.heap(), allocated));
    assert_eq!(
        evaluator
            .heap()
            .generation(visited[0])
            .expect("registered visited root destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(allocated)
            .expect("allocated value destination remains heap-bound"),
        HeapGeneration::Young
    );
}

#[test]
fn transient_value_stack_roots_restore_after_body_error() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let original = Value::int(7);
    let mut roots = [original];
    let bad_id = IrId::new(999);

    let error = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            assert_eq!(eval.transient_value_stack_roots().len(), 1);
            assert!(eval.transient_value_stack_roots()[0].raw_eq(original));
            Err::<(), TreeWalkError>(TreeWalkError::new(
                TreeWalkErrorKind::InvalidNodeId { id: bad_id },
                span,
            ))
        })
        .expect_err("body error propagates");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidNodeId { id } if id == bad_id
    ));
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(roots[0].raw_eq(original));
}

#[test]
fn transient_value_stack_roots_restore_after_body_panic() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let original = Value::int(9);
    let mut roots = [original];

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), TreeWalkError> =
            evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
                assert_eq!(eval.transient_value_stack_roots().len(), 1);
                assert!(eval.transient_value_stack_roots()[0].raw_eq(original));
                panic!("transient root cleanup test panic");
            });
    }));

    assert!(panic.is_err());
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(roots[0].raw_eq(original));
}

#[test]
fn owned_eval_records_gc_stress_boundary_worker_scan() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");

    let scans = outcome.gc_stress_boundary_scans();
    assert_eq!(scans.len(), 1);
    assert!(scans.permanent_shared().is_none());
    let worker_scan = scans.worker().expect("worker boundary scan records");
    assert_eq!(
        worker_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        worker_scan.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert!(scan_has_value_stack_root(worker_scan, outcome.value()));
    assert!(scan_has_object(worker_scan, outcome.value()));
}

#[test]
fn owned_eval_records_gc_stress_boundary_permanent_scan() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let scans = outcome.gc_stress_boundary_scans();
    assert_eq!(scans.len(), 1);
    assert!(scans.worker().is_none());
    let permanent_scan = scans
        .permanent_shared()
        .expect("permanent boundary scan records");
    assert_eq!(
        permanent_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_scan.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert!(scan_has_value_stack_root(permanent_scan, outcome.value()));
    assert!(scan_has_object(permanent_scan, outcome.value()));
}

#[test]
fn attr_path_eval_records_gc_stress_boundary_scan() {
    let ir = lower("{ f = x: x; }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"f".to_vec()],
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
        None,
    )
    .expect("attr-path selection evaluates under GC stress");

    let worker_scan = outcome
        .gc_stress_boundary_scans()
        .worker()
        .expect("selected lambda boundary scan records");
    assert_eq!(
        worker_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert!(scan_has_value_stack_root(worker_scan, outcome.value()));
    assert!(scan_has_object(worker_scan, outcome.value()));
}

#[test]
fn owned_eval_plans_gc_stress_boundary_worker_minor_gc() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("boundary scan plans as minor GC");

    assert_eq!(plans.len(), 1);
    assert!(plans.permanent_shared().is_none());
    let worker_plan = plans.worker().expect("worker boundary plan records");
    assert_eq!(
        worker_plan.roots(),
        &[ResolvedValueGeneration::young(gc_address(outcome.value()))]
    );
    assert_eq!(worker_plan.plan().survivors().len(), 1);
    assert_eq!(
        worker_plan.plan().survivors()[0].address(),
        gc_address(outcome.value())
    );
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_minor_gc() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("boundary scan plans as minor GC");

    assert_eq!(plans.len(), 1);
    assert!(plans.worker().is_none());
    let permanent_plan = plans
        .permanent_shared()
        .expect("permanent boundary plan records");
    let permanent_root = ResolvedValueGeneration::permanent(gc_address(outcome.value()));
    assert_eq!(permanent_plan.roots().len(), 2);
    assert!(
        permanent_plan
            .roots()
            .iter()
            .all(|root| *root == permanent_root)
    );
    assert!(permanent_plan.plan().is_empty());
}

#[test]
fn owned_eval_plans_gc_stress_boundary_worker_relocation_destinations() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);
    let old_base = static_gc_address(0x2000_0000);

    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("boundary scan plans relocation destinations");

    assert_eq!(destinations.len(), 1);
    assert!(destinations.permanent_shared().is_none());
    let worker_destinations = destinations
        .worker()
        .expect("worker relocation destinations record");
    assert_eq!(worker_destinations.destinations().len(), 1);
    assert_eq!(
        worker_destinations.destinations()[0].source(),
        gc_address(outcome.value())
    );
    assert_eq!(
        worker_destinations.destinations()[0].destination(),
        nursery_base
    );
    assert_eq!(
        worker_destinations.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert!(worker_destinations.allocation_plan().nursery_bytes() > 0);
    assert_eq!(worker_destinations.allocation_plan().old_bytes(), 0);
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_relocation_destinations() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan plans relocation destinations");

    assert_eq!(destinations.len(), 1);
    assert!(destinations.worker().is_none());
    let permanent_destinations = destinations
        .permanent_shared()
        .expect("permanent relocation report records");
    assert!(permanent_destinations.destinations().is_empty());
    assert_eq!(permanent_destinations.allocation_plan().nursery_bytes(), 0);
    assert_eq!(permanent_destinations.allocation_plan().old_bytes(), 0);
}

#[test]
fn owned_eval_plans_gc_stress_boundary_worker_commit_metadata() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan builds paired relocation plan");

    assert_eq!(plans.len(), 1);
    assert!(plans.permanent_shared().is_none());
    let worker_plan = plans.worker().expect("worker paired plan records");
    assert_eq!(worker_plan.minor_gc_plan().plan().survivors().len(), 1);
    assert_eq!(
        worker_plan.relocation_destinations().destinations()[0].destination(),
        nursery_base
    );
    let commit = worker_plan
        .commit_plan()
        .expect("paired boundary plan builds commit metadata");
    assert_eq!(
        commit.reference_slots(),
        worker_plan.minor_gc_plan().reference_slots()
    );
    assert_eq!(commit.commit_plan().object_copies().copies().len(), 1);
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination(),
        nursery_base
    );
    assert_eq!(
        commit.commit_plan().forwarding_pointers().pointers().len(),
        1
    );
    assert_eq!(
        commit.reference_slots()[0].value_tag(),
        Some(ValueTag::Lambda)
    );
    let root_writebacks = commit
        .root_writeback_plan()
        .expect("root writeback metadata builds");
    assert_eq!(root_writebacks.len(), 1);
    assert_eq!(
        root_writebacks.writebacks()[0].expected_tag(),
        ValueTag::Lambda
    );
    assert_eq!(
        root_writebacks.writebacks()[0].replacement_tag(),
        ValueTag::Lambda
    );
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_commit_metadata() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan builds paired relocation plan");

    assert_eq!(plans.len(), 1);
    assert!(plans.worker().is_none());
    let permanent_plan = plans
        .permanent_shared()
        .expect("permanent paired plan records");
    assert!(permanent_plan.minor_gc_plan().plan().is_empty());
    assert!(
        permanent_plan
            .relocation_destinations()
            .destinations()
            .is_empty()
    );
    let commit = permanent_plan
        .commit_plan()
        .expect("empty permanent boundary plan builds commit metadata");
    assert!(commit.commit_plan().object_copies().is_empty());
    assert!(commit.commit_plan().reference_rewrites().is_empty());
    assert!(
        commit
            .root_writeback_plan()
            .expect("empty root writeback metadata builds")
            .is_empty()
    );
}

#[test]
fn owned_eval_reports_gc_stress_boundary_worker_commit_preflight() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan builds commit preflight metadata");

    assert_eq!(preflights.len(), 1);
    assert!(preflights.permanent_shared().is_none());
    let preflight = preflights.worker().expect("worker preflight records");
    assert_eq!(
        preflight
            .relocation_plan()
            .minor_gc_plan()
            .plan()
            .survivors()
            .len(),
        1
    );
    assert_eq!(preflight.object_byte_copy_plan().len(), 1);
    assert_eq!(
        preflight.object_byte_copy_plan().requests()[0].destination(),
        nursery_base
    );
    assert_eq!(preflight.forwarding_slots().len(), 1);
    assert_eq!(
        preflight.forwarding_slots()[0].source(),
        gc_address(outcome.value())
    );
    assert!(preflight.forwarding_slots()[0].is_empty());
    assert_eq!(
        preflight.reference_buffer(),
        &[ResolvedValueGeneration::young(gc_address(outcome.value()))]
    );
    assert_eq!(preflight.reference_writeback_plan().len(), 1);
    assert_eq!(
        preflight.reference_writeback_plan().root_writebacks().len(),
        1
    );
    assert_eq!(
        preflight
            .reference_writeback_plan()
            .root_writebacks()
            .writebacks()[0]
            .expected_tag(),
        ValueTag::Lambda
    );
    assert_eq!(
        preflight
            .reference_writeback_plan()
            .root_writebacks()
            .writebacks()[0]
            .replacement_tag(),
        ValueTag::Lambda
    );
    assert!(
        preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .is_empty()
    );
    assert_eq!(preflight.root_value_writeback_slots().len(), 1);
    assert!(
        preflight.root_value_writeback_slots()[0]
            .value()
            .raw_eq(outcome.value())
    );
    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("boundary preflight applies owned writeback slots");
    assert_eq!(application.report().root_writebacks(), 1);
    assert_eq!(application.report().heap_field_writebacks(), 0);
    assert_eq!(
        application.root_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert!(
        application.root_value_writeback_slots()[0]
            .value()
            .raw_eq(relocated_value(ValueTag::Lambda, nursery_base))
    );
    let commit_application = preflight
        .apply_commit_to_owned_buffers()
        .expect("boundary preflight applies owned commit buffers");
    let commit_report = commit_application.report();
    assert_eq!(commit_report.object_copies(), 1);
    assert_eq!(commit_report.copied_to_nursery(), 1);
    assert_eq!(commit_report.promoted_to_old(), 0);
    assert_eq!(commit_report.forwarding_pointers(), 1);
    assert_eq!(commit_report.reference_rewrites(), 1);
    assert_eq!(commit_report.remembered_set_source_edges(), 0);
    assert_eq!(commit_report.remembered_set_published_edges(), 0);
    let object_copy = &commit_application.object_byte_copies()[0];
    assert_eq!(
        object_copy.request(),
        preflight.object_byte_copy_plan().requests()[0]
    );
    assert_eq!(
        object_copy.source_bytes().len(),
        object_copy.request().size_bytes()
    );
    assert_eq!(object_copy.destination_bytes(), object_copy.source_bytes());
    let destination_storage = commit_application.destination_storage();
    assert_eq!(
        destination_storage.copy_report().object_copies(),
        commit_report.object_copies()
    );
    assert_eq!(destination_storage.copy_report().copied_to_nursery(), 1);
    assert_eq!(destination_storage.copy_report().promoted_to_old(), 0);
    assert_eq!(
        destination_storage.copy_report().nursery_payload_bytes(),
        object_copy.request().size_bytes()
    );
    assert_eq!(
        destination_storage.nursery_reserved_bytes(),
        preflight
            .relocation_plan()
            .relocation_destinations()
            .placement_plan()
            .nursery_reserved_bytes()
    );
    assert_eq!(destination_storage.old_reserved_bytes(), 0);
    assert_eq!(
        destination_storage.nursery_destination_bytes(),
        object_copy.source_bytes()
    );
    assert!(destination_storage.old_destination_bytes().is_empty());
    assert_eq!(
        commit_application.forwarding_slots()[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }]
    );
    assert!(commit_application.remembered_set().is_empty());
    let owned_storage_application = preflight
        .apply_commit_to_owned_destination_storage()
        .expect("boundary preflight applies owned destination storage commit");
    let owned_storage_report = owned_storage_application.report();
    assert_eq!(owned_storage_report.object_copies(), 1);
    assert_eq!(owned_storage_report.copied_to_nursery(), 1);
    assert_eq!(owned_storage_report.promoted_to_old(), 0);
    assert_eq!(owned_storage_report.forwarding_pointers(), 1);
    assert_eq!(owned_storage_report.reference_rewrites(), 1);
    assert_eq!(owned_storage_report.remembered_set_source_edges(), 0);
    assert_eq!(owned_storage_report.remembered_set_published_edges(), 0);
    let owned_destination_storage = owned_storage_application.destination_storage();
    assert_eq!(
        owned_destination_storage.copy_report().object_copies(),
        owned_storage_report.object_copies()
    );
    assert_eq!(
        owned_destination_storage.copy_report().copied_to_nursery(),
        1
    );
    assert_eq!(owned_destination_storage.copy_report().promoted_to_old(), 0);
    assert_eq!(
        owned_destination_storage.nursery_reserved_bytes(),
        destination_storage.nursery_reserved_bytes()
    );
    assert_eq!(owned_destination_storage.old_reserved_bytes(), 0);
    assert_eq!(
        owned_destination_storage.nursery_destination_bytes(),
        object_copy.source_bytes()
    );
    assert!(owned_destination_storage.old_destination_bytes().is_empty());
    let owned_forwarded_value = owned_storage_application.forwarding_slots()[0]
        .forwarded_value()
        .expect("owned-storage commit installs forwarding");
    let ResolvedValueGeneration::Heap {
        address: owned_nursery_base,
        generation: HeapGeneration::Young,
    } = owned_forwarded_value
    else {
        panic!("owned-storage copied survivor remains young");
    };
    assert_eq!(
        owned_storage_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: owned_nursery_base,
            generation: HeapGeneration::Young,
        }]
    );
    assert!(owned_storage_application.remembered_set().is_empty());
    assert!(owned_storage_application.card_table().is_empty());

    let applications = preflights
        .apply_reference_writebacks_to_owned_slots()
        .expect("boundary preflights apply owned writeback slots");
    assert_eq!(applications.len(), 1);
    assert_eq!(applications.worker(), Some(&application));
    assert!(applications.permanent_shared().is_none());
    let commit_applications = preflights
        .apply_commits_to_owned_buffers()
        .expect("boundary preflights apply owned commit buffers");
    assert_eq!(commit_applications.len(), 1);
    assert_eq!(commit_applications.worker(), Some(&commit_application));
    assert!(commit_applications.permanent_shared().is_none());
    let owned_storage_applications = preflights
        .apply_commits_to_owned_destination_storage()
        .expect("boundary preflights apply owned destination storage commits");
    assert_eq!(owned_storage_applications.len(), 1);
    assert!(owned_storage_applications.permanent_shared().is_none());
    let aggregate_owned_storage_application = owned_storage_applications
        .worker()
        .expect("worker boundary owned-storage commit application is present");
    assert_eq!(
        aggregate_owned_storage_application.report(),
        owned_storage_application.report()
    );
    assert_eq!(
        aggregate_owned_storage_application
            .destination_storage()
            .copy_report(),
        owned_storage_application
            .destination_storage()
            .copy_report()
    );
    assert_eq!(
        aggregate_owned_storage_application
            .destination_storage()
            .nursery_reserved_bytes(),
        owned_destination_storage.nursery_reserved_bytes()
    );
    assert_eq!(
        aggregate_owned_storage_application
            .destination_storage()
            .old_reserved_bytes(),
        owned_destination_storage.old_reserved_bytes()
    );
    assert_eq!(
        aggregate_owned_storage_application
            .destination_storage()
            .nursery_destination_bytes(),
        object_copy.source_bytes()
    );
    assert!(
        aggregate_owned_storage_application
            .destination_storage()
            .old_destination_bytes()
            .is_empty()
    );
    let aggregate_forwarded_value = aggregate_owned_storage_application.forwarding_slots()[0]
        .forwarded_value()
        .expect("aggregate owned-storage commit installs forwarding");
    let ResolvedValueGeneration::Heap {
        address: aggregate_nursery_base,
        generation: HeapGeneration::Young,
    } = aggregate_forwarded_value
    else {
        panic!("aggregate owned-storage copied survivor remains young");
    };
    assert_eq!(
        aggregate_owned_storage_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: aggregate_nursery_base,
            generation: HeapGeneration::Young,
        }]
    );
    assert!(
        aggregate_owned_storage_application
            .remembered_set()
            .is_empty()
    );
    assert!(aggregate_owned_storage_application.card_table().is_empty());
}

#[test]
fn owned_eval_runs_gc_stress_boundary_worker_commit_dry_run() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan runs owned commit dry-run");

    assert_eq!(dry_run.len(), 1);
    assert!(!dry_run.is_empty());
    assert!(dry_run.preflights().permanent_shared().is_none());
    assert!(dry_run.reference_writebacks().permanent_shared().is_none());
    assert!(dry_run.commit_applications().permanent_shared().is_none());
    assert!(
        dry_run
            .owned_storage_commit_applications()
            .permanent_shared()
            .is_none()
    );
    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.object_copies(), 1);
    assert_eq!(summary.copied_to_nursery(), 1);
    assert_eq!(summary.promoted_to_old(), 0);
    assert!(summary.object_copy_bytes() > 0);
    assert_eq!(summary.object_copy_bytes(), summary.copy_to_nursery_bytes());
    assert_eq!(summary.promote_to_old_bytes(), 0);
    assert_eq!(summary.forwarding_pointers(), 1);
    assert_eq!(summary.reference_rewrites(), 1);
    assert_eq!(summary.root_writebacks(), 1);
    assert_eq!(summary.heap_field_writebacks(), 0);
    assert_eq!(summary.reference_writebacks(), 1);
    assert_eq!(summary.remembered_set_source_edges(), 0);
    assert_eq!(summary.remembered_set_published_edges(), 0);

    let preflight = dry_run
        .preflights()
        .worker()
        .expect("worker dry-run preflight records");
    let writeback_application = dry_run
        .reference_writebacks()
        .worker()
        .expect("worker dry-run writebacks record");
    let commit_application = dry_run
        .commit_applications()
        .worker()
        .expect("worker dry-run commit records");

    assert_eq!(preflight.object_byte_copy_plan().len(), 1);
    assert_eq!(
        preflight.object_copy_bytes(),
        preflight.object_byte_copy_plan().copy_to_nursery_bytes()
    );
    assert_eq!(preflight.promote_to_old_bytes(), 0);
    assert_eq!(summary.object_copy_bytes(), preflight.object_copy_bytes());
    assert_eq!(
        writeback_application.report().root_writebacks(),
        preflight.reference_writeback_plan().root_writebacks().len()
    );
    assert_eq!(
        writeback_application.report().heap_field_writebacks(),
        preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .len()
    );
    assert_eq!(
        writeback_application.root_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert!(
        writeback_application.root_value_writeback_slots()[0]
            .value()
            .raw_eq(relocated_value(ValueTag::Lambda, nursery_base))
    );

    let commit_report = commit_application.report();
    assert_eq!(
        commit_report.object_copies(),
        preflight.object_byte_copy_plan().len()
    );
    assert_eq!(
        commit_report.forwarding_pointers(),
        preflight.forwarding_slots().len()
    );
    assert_eq!(
        commit_report.reference_rewrites(),
        writeback_application.report().writebacks()
    );
    assert_eq!(commit_report.copied_to_nursery(), 1);
    assert_eq!(commit_report.promoted_to_old(), 0);

    let object_copy = &commit_application.object_byte_copies()[0];
    assert_eq!(
        object_copy.request(),
        preflight.object_byte_copy_plan().requests()[0]
    );
    assert_eq!(object_copy.destination_bytes(), object_copy.source_bytes());
    assert_eq!(
        commit_application.forwarding_slots()[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }]
    );
    let owned_storage_commit_application = dry_run
        .owned_storage_commit_applications()
        .worker()
        .expect("worker dry-run owned-storage commit records");
    assert_eq!(owned_storage_commit_application.report(), commit_report);
    assert_eq!(
        owned_storage_commit_application
            .destination_storage()
            .copy_report()
            .object_copies(),
        commit_report.object_copies()
    );
    assert_eq!(
        owned_storage_commit_application
            .destination_storage()
            .nursery_destination_bytes(),
        object_copy.source_bytes()
    );
    assert!(
        owned_storage_commit_application
            .destination_storage()
            .old_destination_bytes()
            .is_empty()
    );
    let owned_storage_forwarded_value = owned_storage_commit_application.forwarding_slots()[0]
        .forwarded_value()
        .expect("worker dry-run owned-storage commit installs forwarding");
    let ResolvedValueGeneration::Heap {
        address: owned_storage_nursery_base,
        generation: HeapGeneration::Young,
    } = owned_storage_forwarded_value
    else {
        panic!("worker dry-run owned-storage survivor remains young");
    };
    assert_eq!(
        owned_storage_commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: owned_storage_nursery_base,
            generation: HeapGeneration::Young,
        }]
    );

    let mut writeback_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live reference writebacks");
    assert!(
        writeback_outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let live_writeback_dry_run = writeback_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run installs live reference writebacks");
    assert_eq!(live_writeback_dry_run.reference_writebacks_installed(), 1);
    assert_eq!(
        live_writeback_dry_run
            .reference_writeback_install_report()
            .root_writebacks(),
        1
    );
    assert_eq!(
        live_writeback_dry_run
            .reference_writeback_install_report()
            .heap_field_writebacks(),
        0
    );
    let live_writebacks = writeback_outcome.gc_stress_boundary_minor_gc_reference_writebacks();
    let live_worker_writebacks = live_writebacks.worker().expect("worker writebacks install");
    let dry_worker_writebacks = live_writeback_dry_run
        .dry_run()
        .reference_writebacks()
        .worker()
        .expect("dry worker writebacks record");
    assert_eq!(live_writebacks.len(), 1);
    assert_eq!(live_writebacks.install_report().writebacks(), 1);
    assert_eq!(live_worker_writebacks, dry_worker_writebacks);
    assert_eq!(
        live_worker_writebacks.root_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert!(
        live_worker_writebacks.root_value_writeback_slots()[0]
            .value()
            .raw_eq(relocated_value(ValueTag::Lambda, nursery_base))
    );
    let writebacks_before_repeat = live_writebacks.clone();
    let repeat_error = writeback_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("occupied live reference writebacks reject repeat install");
    assert_eq!(
        repeat_error,
        EvalHeapError::BoundaryMinorGcLiveReferenceWritebacksAlreadyInstalled { existing: 1 }
    );
    assert_eq!(
        writeback_outcome.gc_stress_boundary_minor_gc_reference_writebacks(),
        &writebacks_before_repeat
    );

    let mut destination_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live destination storage");
    assert!(
        destination_outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    let live_destination_dry_run = destination_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run installs live destination bytes");
    let live_destination_commit = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live destination worker commit records");
    let live_destination_object_copy = &live_destination_commit.object_byte_copies()[0];
    let live_destination_storage =
        destination_outcome.gc_stress_boundary_minor_gc_destination_storage();
    assert_eq!(live_destination_dry_run.object_copies_installed(), 1);
    assert_eq!(live_destination_storage.len(), 1);
    assert_eq!(
        live_destination_storage.install_report(),
        live_destination_dry_run.destination_storage_install_report()
    );
    assert_eq!(
        live_destination_storage.object_bytes()[0].request(),
        live_destination_object_copy.request()
    );
    assert_eq!(
        live_destination_storage.object_bytes()[0].destination_bytes(),
        live_destination_object_copy.destination_bytes()
    );
    let destination_storage_before_repeat = live_destination_storage.clone();
    let repeat_error = destination_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("occupied live destination storage rejects repeat install");
    assert_eq!(
        repeat_error,
        EvalHeapError::BoundaryMinorGcLiveDestinationStorageAlreadyInstalled { existing: 1 }
    );
    assert_eq!(
        destination_outcome.gc_stress_boundary_minor_gc_destination_storage(),
        &destination_storage_before_repeat
    );

    let mut object_generation_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live object generations");
    assert!(
        object_generation_outcome
            .gc_stress_boundary_minor_gc_object_generations()
            .is_empty()
    );
    let live_object_generation_dry_run = object_generation_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_object_generations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run installs live object generations");
    let live_object_generation_commit = live_object_generation_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live object-generation worker commit records");
    let live_object_generation_copy = &live_object_generation_commit.object_byte_copies()[0];
    let live_object_generations =
        object_generation_outcome.gc_stress_boundary_minor_gc_object_generations();
    assert_eq!(
        live_object_generation_dry_run.object_generations_installed(),
        1
    );
    assert_eq!(live_object_generations.len(), 1);
    assert_eq!(
        live_object_generations.install_report(),
        live_object_generation_dry_run.object_generation_install_report()
    );
    assert_eq!(
        live_object_generations.object_generations()[0].source(),
        live_object_generation_copy.request().source()
    );
    assert_eq!(
        live_object_generations.object_generations()[0].destination(),
        live_object_generation_copy.request().destination()
    );
    assert_eq!(
        live_object_generations.object_generations()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        live_object_generations.object_generations()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        live_object_generations.object_generations()[0].request(),
        live_object_generation_copy.request()
    );
    let object_generations_before_repeat = live_object_generations.clone();
    let repeat_error = object_generation_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_object_generations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("occupied live object generations reject repeat install");
    assert_eq!(
        repeat_error,
        EvalHeapError::BoundaryMinorGcLiveObjectGenerationsAlreadyInstalled { existing: 1 }
    );
    assert_eq!(
        object_generation_outcome.gc_stress_boundary_minor_gc_object_generations(),
        &object_generations_before_repeat
    );

    let mut writeback_binding_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live writeback destination bindings");
    assert!(
        writeback_binding_outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    let live_writeback_binding_dry_run = writeback_binding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run installs live writeback destination bindings");
    let live_writeback_binding_commit = live_writeback_binding_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live writeback destination-binding worker commit records");
    let live_writeback_binding_copy = &live_writeback_binding_commit.object_byte_copies()[0];
    let live_writeback_destination_bindings =
        writeback_binding_outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings();
    assert_eq!(
        live_writeback_binding_dry_run.writeback_destination_bindings_installed(),
        1
    );
    assert_eq!(
        live_writeback_binding_dry_run.root_writeback_destination_bindings_installed(),
        1
    );
    assert_eq!(
        live_writeback_binding_dry_run.heap_field_writeback_destination_bindings_installed(),
        0
    );
    assert_eq!(live_writeback_destination_bindings.len(), 1);
    assert_eq!(
        live_writeback_destination_bindings.install_report(),
        live_writeback_binding_dry_run.writeback_destination_binding_install_report()
    );
    assert_eq!(
        live_writeback_destination_bindings
            .root_writeback_bindings()
            .len(),
        1
    );
    assert!(
        live_writeback_destination_bindings
            .heap_field_writeback_bindings()
            .is_empty()
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].root_source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].replacement_tag(),
        ValueTag::Lambda
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].destination(),
        nursery_base
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].request(),
        live_writeback_binding_copy.request()
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].destination_bytes(),
        live_writeback_binding_copy.destination_bytes()
    );
    let writeback_destination_bindings_before_repeat = live_writeback_destination_bindings.clone();
    let repeat_error = writeback_binding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("occupied live writeback destination bindings reject repeat install");
    assert_eq!(
        repeat_error,
        EvalHeapError::BoundaryMinorGcLiveWritebackDestinationBindingsAlreadyInstalled {
            existing: 1
        }
    );
    assert_eq!(
        writeback_binding_outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings(),
        &writeback_destination_bindings_before_repeat
    );

    let mut forwarding_binding_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live forwarding destination bindings");
    let forwarding_binding_source = gc_address(forwarding_binding_outcome.value());
    assert!(
        forwarding_binding_outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
            .is_empty()
    );
    assert_eq!(
        forwarding_binding_outcome
            .heap()
            .minor_gc_forwarding_value_at(forwarding_binding_source)
            .expect("forwarding binding source is known"),
        None
    );
    let live_forwarding_binding_dry_run = forwarding_binding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run installs live forwarding destination bindings");
    let live_forwarding_binding_commit = live_forwarding_binding_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live forwarding destination-binding worker commit records");
    let live_forwarding_binding_slot = live_forwarding_binding_commit.forwarding_slots()[0];
    let live_forwarding_binding_copy = &live_forwarding_binding_commit.object_byte_copies()[0];
    let live_forwarding_destination_bindings = forwarding_binding_outcome
        .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata();
    assert_eq!(
        live_forwarding_binding_dry_run.forwarding_destination_bindings_installed(),
        1
    );
    assert_eq!(live_forwarding_destination_bindings.len(), 1);
    assert_eq!(
        live_forwarding_destination_bindings.install_report(),
        live_forwarding_binding_dry_run.forwarding_destination_binding_install_report()
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0].source(),
        live_forwarding_binding_slot.source()
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0].destination(),
        nursery_base
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0].forwarded_value(),
        live_forwarding_binding_slot
            .forwarded_value()
            .expect("planned forwarding value is installed in metadata")
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0].request(),
        live_forwarding_binding_copy.request()
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0]
            .destination_bytes(),
        live_forwarding_binding_copy.destination_bytes()
    );
    assert_eq!(
        forwarding_binding_outcome
            .heap()
            .minor_gc_forwarding_value_at(forwarding_binding_source)
            .expect("forwarding binding source remains known"),
        None
    );
    let header_plan_error = forwarding_binding_outcome
        .gc_stress_boundary_minor_gc_forwarding_header_write_plan()
        .expect_err("forwarding header plan requires the live forwarding cell");
    assert!(matches!(
        header_plan_error,
        EvalHeapError::BoundaryMinorGcForwardingHeaderWriteMissingForwarding {
            source_address,
            expected
        } if source_address == forwarding_binding_source
            && expected
                == live_forwarding_binding_slot
                    .forwarded_value()
                    .expect("planned forwarding value exists")
    ));
    let forwarding_destination_bindings_before_repeat =
        live_forwarding_destination_bindings.clone();
    let stale_forwarded_value = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x3000_0000),
        generation: HeapGeneration::Young,
    };
    forwarding_binding_outcome
        .heap
        .install_collector_poll_minor_gc_forwarding_slots(&[
            MinorGcForwardingSlot::with_forwarded_value(
                forwarding_binding_source,
                stale_forwarded_value,
            ),
        ])
        .expect("stale live forwarding value installs for header-plan mismatch test");
    let header_plan_error = forwarding_binding_outcome
        .gc_stress_boundary_minor_gc_forwarding_header_write_plan()
        .expect_err("forwarding header plan rejects stale live forwarding value");
    assert!(matches!(
        header_plan_error,
        EvalHeapError::BoundaryMinorGcForwardingHeaderWriteForwardingMismatch {
            source_address,
            expected,
            actual
        } if source_address == forwarding_binding_source
            && expected
                == live_forwarding_binding_slot
                    .forwarded_value()
                    .expect("planned forwarding value exists")
            && actual == stale_forwarded_value
    ));
    let repeat_error = forwarding_binding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("occupied live forwarding destination bindings reject repeat install");
    assert_eq!(
        repeat_error,
        EvalHeapError::BoundaryMinorGcLiveForwardingDestinationBindingsAlreadyInstalled {
            existing: 1
        }
    );
    assert_eq!(
        forwarding_binding_outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata(),
        &forwarding_destination_bindings_before_repeat
    );

    let mut forwarding_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live forwarding");
    assert_eq!(
        forwarding_outcome
            .heap()
            .minor_gc_forwarding_value_at(gc_address(forwarding_outcome.value()))
            .expect("forwarding source is known"),
        None
    );
    let live_forwarding_dry_run = forwarding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run installs live forwarding");
    let live_forwarding_commit = live_forwarding_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live forwarding worker commit records");
    let live_forwarding_slot = live_forwarding_commit.forwarding_slots()[0];
    assert_eq!(live_forwarding_dry_run.forwarding_pointers_installed(), 1);
    assert_eq!(
        forwarding_outcome
            .heap()
            .minor_gc_forwarding_value_at(live_forwarding_slot.source())
            .expect("forwarding source remains known"),
        live_forwarding_slot.forwarded_value()
    );
    let forwarding_before_repeat = forwarding_outcome
        .heap()
        .minor_gc_forwarding_value_at(live_forwarding_slot.source())
        .expect("forwarding source remains known before repeat");
    forwarding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("occupied live forwarding slot rejects repeat install");
    assert_eq!(
        forwarding_outcome
            .heap()
            .minor_gc_forwarding_value_at(live_forwarding_slot.source())
            .expect("forwarding source remains known after repeat"),
        forwarding_before_repeat
    );

    let live_dirty_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(live_dirty_source)
        .expect("single-tier live dirty card marks");
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);

    let live_state_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run publishes live remembered set");
    let live_worker_commit = live_state_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live worker commit records");
    assert!(live_state_dry_run.remembered_set_published());
    assert_eq!(live_state_dry_run.card_table_dirty_cards_cleared(), 1);
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        live_worker_commit.remembered_set()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 0);
}

#[test]
fn owned_eval_installs_gc_stress_boundary_live_metadata_together() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for live metadata");
    let original_value = outcome.value();
    let original_address = gc_address(original_value);
    let nursery_base = static_gc_address(0x1000_0000);
    let old_base = static_gc_address(0x2000_0000);

    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_object_generations()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_object_generation_bindings()
            .expect("empty object-generation binding report builds")
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_object_generation_write_plan()
            .expect("empty object-generation write plan builds")
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_bindings()
            .expect("empty forwarding destination binding report builds")
            .is_empty()
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell is readable"),
        None
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_root_writeback_destination_bindings()
            .expect("empty binding report builds")
            .is_empty()
    );

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("single-tier worker dry-run installs live metadata");
    let summary = live_metadata.dry_run().summary();
    assert_eq!(live_metadata.forwarding_pointers_installed(), 1);
    assert_eq!(
        live_metadata.forwarding_pointers_installed(),
        summary.forwarding_pointers()
    );
    assert_eq!(
        live_metadata.forwarding_destination_bindings_installed(),
        summary.forwarding_pointers()
    );
    assert_eq!(live_metadata.object_copies_installed(), 1);
    assert_eq!(
        live_metadata.object_copies_installed(),
        summary.object_copies()
    );
    assert_eq!(live_metadata.object_generations_installed(), 1);
    assert_eq!(
        live_metadata.object_generations_installed(),
        summary.object_copies()
    );
    assert_eq!(live_metadata.reference_writebacks_installed(), 1);
    assert_eq!(
        live_metadata.reference_writebacks_installed(),
        summary.reference_writebacks()
    );
    assert_eq!(live_metadata.writeback_destination_bindings_installed(), 1);
    assert_eq!(
        live_metadata.root_writeback_destination_bindings_installed(),
        summary.reference_writebacks()
    );
    assert_eq!(
        live_metadata.heap_field_writeback_destination_bindings_installed(),
        0
    );
    assert!(live_metadata.remembered_set_published());
    assert_eq!(live_metadata.card_table_dirty_cards_cleared(), 0);
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell remains readable"),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );

    let live_destination_storage = outcome.gc_stress_boundary_minor_gc_destination_storage();
    let live_object_copy = live_metadata
        .dry_run()
        .commit_applications()
        .worker()
        .expect("worker live metadata commit records")
        .object_byte_copies()
        .first()
        .expect("worker copied one object");
    assert_eq!(live_destination_storage.len(), 1);
    assert_eq!(
        live_destination_storage.install_report().object_copies(),
        summary.object_copies()
    );
    assert_eq!(
        live_destination_storage.object_bytes()[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        live_destination_storage.object_bytes()[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );
    let live_object_generations = outcome.gc_stress_boundary_minor_gc_object_generations();
    assert_eq!(live_object_generations.len(), 1);
    assert_eq!(
        live_object_generations.install_report().objects(),
        summary.object_copies()
    );
    assert_eq!(
        live_object_generations.install_report().copied_to_nursery(),
        summary.object_copies()
    );
    assert_eq!(
        live_object_generations.install_report().promoted_to_old(),
        0
    );
    assert_eq!(
        live_object_generations.object_generations()[0].source(),
        live_object_copy.request().source()
    );
    assert_eq!(
        live_object_generations.object_generations()[0].destination(),
        nursery_base
    );
    assert_eq!(
        live_object_generations.object_generations()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        live_object_generations.object_generations()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        live_object_generations.object_generations()[0].request(),
        live_object_copy.request()
    );
    let object_generation_bindings = outcome
        .gc_stress_boundary_minor_gc_destination_object_generation_bindings()
        .expect("destination object-generation bindings validate");
    assert_eq!(object_generation_bindings.len(), 1);
    assert_eq!(
        object_generation_bindings[0].source(),
        live_object_copy.request().source()
    );
    assert_eq!(object_generation_bindings[0].destination(), nursery_base);
    assert_eq!(
        object_generation_bindings[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        object_generation_bindings[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        object_generation_bindings[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        object_generation_bindings[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );
    let object_generation_write_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates installed live metadata");
    assert_eq!(object_generation_write_plan.len(), 1);
    assert_eq!(
        object_generation_write_plan.report().objects(),
        summary.object_copies()
    );
    assert_eq!(
        object_generation_write_plan.report().copied_to_nursery(),
        summary.object_copies()
    );
    assert_eq!(object_generation_write_plan.report().promoted_to_old(), 0);
    assert_eq!(
        object_generation_write_plan.report().payload_bytes(),
        live_object_copy.destination_bytes().len()
    );
    assert_eq!(
        object_generation_write_plan.writes()[0].source(),
        live_object_copy.request().source()
    );
    assert_eq!(
        object_generation_write_plan.writes()[0].destination(),
        nursery_base
    );
    assert_eq!(
        object_generation_write_plan.writes()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        object_generation_write_plan.writes()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        object_generation_write_plan.writes()[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        object_generation_write_plan.writes()[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );
    let forwarding_destination_bindings = outcome
        .gc_stress_boundary_minor_gc_forwarding_destination_bindings()
        .expect("forwarding destination bindings validate");
    assert_eq!(forwarding_destination_bindings.len(), 1);
    assert_eq!(
        forwarding_destination_bindings[0].source(),
        original_address
    );
    assert_eq!(
        forwarding_destination_bindings[0].destination(),
        nursery_base
    );
    assert_eq!(
        forwarding_destination_bindings[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        forwarding_destination_bindings[0].forwarded_value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        forwarding_destination_bindings[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        forwarding_destination_bindings[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );
    let live_forwarding_destination_bindings =
        outcome.gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata();
    assert_eq!(live_forwarding_destination_bindings.len(), 1);
    assert_eq!(
        live_forwarding_destination_bindings
            .install_report()
            .bindings(),
        summary.forwarding_pointers()
    );
    assert_eq!(
        live_forwarding_destination_bindings.forwarding_destination_bindings()[0],
        forwarding_destination_bindings[0]
    );
    let forwarding_header_write_plan = outcome
        .gc_stress_boundary_minor_gc_forwarding_header_write_plan()
        .expect("forwarding header write plan validates installed live metadata");
    assert_eq!(forwarding_header_write_plan.len(), 1);
    assert_eq!(
        forwarding_header_write_plan.report().headers(),
        summary.forwarding_pointers()
    );
    assert_eq!(
        forwarding_header_write_plan.report().copied_to_nursery(),
        summary.object_copies()
    );
    assert_eq!(forwarding_header_write_plan.report().promoted_to_old(), 0);
    assert_eq!(
        forwarding_header_write_plan.report().payload_bytes(),
        live_object_copy.destination_bytes().len()
    );
    assert_eq!(
        forwarding_header_write_plan.writes()[0].source(),
        original_address
    );
    assert_eq!(
        forwarding_header_write_plan.writes()[0].destination(),
        nursery_base
    );
    assert_eq!(
        forwarding_header_write_plan.writes()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        forwarding_header_write_plan.writes()[0].forwarded_value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        forwarding_header_write_plan.writes()[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        forwarding_header_write_plan.writes()[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );

    let live_writebacks = outcome.gc_stress_boundary_minor_gc_reference_writebacks();
    let live_worker_writebacks = live_writebacks
        .worker()
        .expect("worker live metadata writebacks install");
    assert_eq!(live_writebacks.install_report().writebacks(), 1);
    assert_eq!(
        live_worker_writebacks.root_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert!(
        live_worker_writebacks.root_value_writeback_slots()[0]
            .value()
            .raw_eq(relocated_value(ValueTag::Lambda, nursery_base))
    );
    let live_writeback_destination_bindings =
        outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings();
    assert_eq!(live_writeback_destination_bindings.len(), 1);
    assert_eq!(
        live_writeback_destination_bindings
            .install_report()
            .root_writeback_bindings(),
        summary.reference_writebacks()
    );
    assert_eq!(
        live_writeback_destination_bindings
            .install_report()
            .heap_field_writeback_bindings(),
        0
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].root_source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].replacement_tag(),
        ValueTag::Lambda
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].destination(),
        nursery_base
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        live_writeback_destination_bindings.root_writeback_bindings()[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );
    assert!(
        live_writeback_destination_bindings
            .heap_field_writeback_bindings()
            .is_empty()
    );
    let bindings = outcome
        .gc_stress_boundary_minor_gc_root_writeback_destination_bindings()
        .expect("root writeback destination bindings validate");
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        bindings[0].root_source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(bindings[0].replacement_tag(), ValueTag::Lambda);
    assert_eq!(bindings[0].destination(), nursery_base);
    assert_eq!(bindings[0].generation(), HeapGeneration::Young);
    assert_eq!(bindings[0].request(), live_object_copy.request());
    assert_eq!(
        bindings[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );
    let root_writeback_write_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback write plan validates installed live metadata");
    assert_eq!(root_writeback_write_plan.len(), 1);
    assert_eq!(
        root_writeback_write_plan.report().roots(),
        summary.reference_writebacks()
    );
    assert_eq!(
        root_writeback_write_plan.report().copied_to_nursery(),
        summary.reference_writebacks()
    );
    assert_eq!(root_writeback_write_plan.report().promoted_to_old(), 0);
    assert_eq!(
        root_writeback_write_plan.report().payload_bytes(),
        live_object_copy.destination_bytes().len()
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].root_source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].replacement_tag(),
        ValueTag::Lambda
    );
    assert!(
        root_writeback_write_plan.writes()[0]
            .replacement_value()
            .raw_eq(relocated_value(ValueTag::Lambda, nursery_base))
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].destination(),
        nursery_base
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].replacement_metadata(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].request(),
        live_object_copy.request()
    );
    assert_eq!(
        root_writeback_write_plan.writes()[0].destination_bytes(),
        live_object_copy.destination_bytes()
    );

    let destination_storage_before_repeat = live_destination_storage.clone();
    let forwarding_destination_bindings_before_repeat =
        live_forwarding_destination_bindings.clone();
    let object_generations_before_repeat = live_object_generations.clone();
    let writebacks_before_repeat = live_writebacks.clone();
    let writeback_destination_bindings_before_repeat = live_writeback_destination_bindings.clone();
    let repeat_error = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect_err("occupied live metadata rejects repeat install before mutation");
    assert_eq!(
        repeat_error,
        EvalHeapError::BoundaryMinorGcLiveDestinationStorageAlreadyInstalled { existing: 1 }
    );
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_destination_storage(),
        &destination_storage_before_repeat
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata(),
        &forwarding_destination_bindings_before_repeat
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_object_generations(),
        &object_generations_before_repeat
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_reference_writebacks(),
        &writebacks_before_repeat
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings(),
        &writeback_destination_bindings_before_repeat
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell remains readable"),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );
}

#[test]
fn existing_destination_live_metadata_preflights_object_body_generations_before_install() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let original_address = gc_address(original_value);
    let destination_address = gc_address(destination_value);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), destination_address),
        )
        .expect("existing-destination live metadata preflight installs metadata");
    let object_body_report = live_metadata
        .object_body_and_generation_write_report()
        .body_write_report();
    let object_generation_report = live_metadata
        .object_body_and_generation_write_report()
        .generation_write_report();

    assert_eq!(live_metadata.object_body_preflight_objects(), 1);
    assert_eq!(live_metadata.object_generation_preflight_objects(), 1);
    assert_eq!(object_body_report.promoted_to_old(), 1);
    assert_eq!(object_generation_report.promoted_to_old(), 1);
    assert_eq!(live_metadata.live_metadata().object_copies_installed(), 1);
    assert_eq!(
        live_metadata.live_metadata().object_generations_installed(),
        1
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell remains readable"),
        Some(ResolvedValueGeneration::Heap {
            address: destination_address,
            generation: HeapGeneration::Old,
        })
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation metadata was installed");
    let write = &object_generation_plan.writes()[0];
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                write.request(),
                ValueTag::Lambda
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert!(outcome.value().raw_eq(original_value));
}

#[test]
fn existing_destination_live_metadata_rejects_synthetic_destination_before_metadata_install() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let original_address = gc_address(original_value);
    let destination_generation_before = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");
    let missing_destination = static_gc_address(0x1000_0000);

    let err = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(missing_destination, static_gc_address(0x2000_0000)),
        )
        .expect_err("strict live metadata rejects synthetic destinations before install");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectBodyDestination {
            destination: missing_destination,
        }
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_object_generations()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell remains readable"),
        None
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("unrelated destination remains heap-bound"),
        destination_generation_before
    );
    assert!(outcome.value().raw_eq(original_value));
}

#[test]
fn existing_destination_live_commit_rejects_synthetic_destination_before_metadata_install() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let original_address = gc_address(original_value);
    let destination_generation_before = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");
    let missing_destination = static_gc_address(0x1000_0000);

    let err = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_commit(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(missing_destination, static_gc_address(0x2000_0000)),
        )
        .expect_err(
            "composed existing-destination commit rejects synthetic destinations before install",
        );

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectBodyDestination {
            destination: missing_destination,
        }
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_object_generations()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell remains readable"),
        None
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("unrelated destination remains heap-bound"),
        destination_generation_before
    );
    assert!(outcome.value().raw_eq(original_value));
}

#[test]
fn live_object_bodies_bind_existing_copied_destination_record_body() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with an existing copied destination");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    assert_eq!(object_generation_plan.len(), 1);
    let write = &object_generation_plan.writes()[0];
    assert_eq!(write.source(), gc_address(original_value));
    assert_eq!(write.destination(), destination_address);
    assert_eq!(write.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(write.generation(), HeapGeneration::Young);

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_bodies()
        .expect("live copied destination binds existing destination record body");

    assert_eq!(report.objects(), 1);
    assert_eq!(report.copied_to_nursery(), 1);
    assert_eq!(report.promoted_to_old(), 0);
    assert_eq!(report.payload_bytes(), write.destination_bytes().len());
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(write.request(), ValueTag::Lambda)
        .expect("copied destination body is bound after live body applicator");
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("body-only applicator leaves copied generation unchanged"),
        HeapGeneration::Young
    );
    assert!(outcome.value().raw_eq(original_value));
}

#[test]
fn live_object_bodies_bind_existing_promoted_destination_record_body() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), destination_address),
        )
        .expect("live metadata installs with an existing old destination");
    assert_eq!(live_metadata.object_copies_installed(), 1);
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    let write = &object_generation_plan.writes()[0];
    assert_eq!(write.source(), gc_address(original_value));
    assert_eq!(write.destination(), destination_address);
    assert_eq!(write.action(), MinorGcSurvivorAction::PromoteToOld);
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(write.request(), ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == destination_address
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination starts heap-bound"),
        HeapGeneration::Young
    );

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_bodies()
        .expect("live destination bytes bind existing destination record body");

    assert_eq!(report.objects(), 1);
    assert_eq!(report.copied_to_nursery(), 0);
    assert_eq!(report.promoted_to_old(), 1);
    assert_eq!(report.payload_bytes(), write.destination_bytes().len());
    assert!(outcome.value().raw_eq(original_value));
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(write.request(), ValueTag::Lambda)
        .expect("destination body is bound after live body applicator");
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("body-only applicator leaves generation unchanged"),
        HeapGeneration::Young
    );
}

#[test]
fn live_object_bodies_reject_unknown_destination_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let unchanged_destination_request = outcome
        .heap()
        .collector_poll_minor_gc_object_byte_copy_request_for_test(
            original_value,
            destination_value,
            MinorGcSurvivorAction::PromoteToOld,
        )
        .expect("test request for existing destination builds");
    let destination_generation_before = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");
    let missing_destination = static_gc_address(0x1000_0000);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(missing_destination, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with synthetic destination storage");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    assert_eq!(object_generation_plan.len(), 1);
    assert_eq!(
        object_generation_plan.writes()[0].destination(),
        missing_destination
    );

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_bodies()
        .expect_err("synthetic destination body remains unsupported");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectBodyDestination {
            destination: missing_destination,
        }
    );
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("unrelated destination remains heap-bound"),
        destination_generation_before
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                unchanged_destination_request,
                ValueTag::Lambda,
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == gc_address(destination_value)
    ));
}

#[test]
fn live_object_generations_update_existing_destination_record_generation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), destination_address),
        )
        .expect("live metadata installs with an existing old destination");
    assert_eq!(live_metadata.object_generations_installed(), 1);
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    assert_eq!(object_generation_plan.len(), 1);
    let write = &object_generation_plan.writes()[0];
    assert_eq!(write.source(), gc_address(original_value));
    assert_eq!(write.destination(), destination_address);
    assert_eq!(write.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(write.generation(), HeapGeneration::Old);
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination starts heap-bound"),
        HeapGeneration::Young
    );
    assert!(outcome.value().raw_eq(original_value));

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_generations()
        .expect("live object-generation metadata writes existing destination record");

    assert_eq!(report.objects(), 1);
    assert_eq!(report.copied_to_nursery(), 0);
    assert_eq!(report.promoted_to_old(), 1);
    assert_eq!(report.payload_bytes(), write.destination_bytes().len());
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination remains heap-bound"),
        HeapGeneration::Old
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(write.request(), ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == destination_address
    ));
}

#[test]
fn live_object_generations_reject_unknown_destination_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_generation_before = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");
    let missing_destination = static_gc_address(0x1000_0000);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(missing_destination, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with synthetic destination storage");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    assert_eq!(object_generation_plan.len(), 1);
    assert_eq!(
        object_generation_plan.writes()[0].destination(),
        missing_destination
    );

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_generations()
        .expect_err("synthetic destination record remains unsupported");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectGenerationDestination {
            destination: missing_destination,
        }
    );
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .generation(original_value)
            .expect("source remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("unrelated destination remains heap-bound"),
        destination_generation_before
    );
}

#[test]
fn live_object_body_generations_validate_existing_promoted_destination_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), destination_address),
        )
        .expect("live metadata installs with an existing promoted destination");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    let write = &object_generation_plan.writes()[0];
    assert_eq!(write.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination starts heap-bound"),
        HeapGeneration::Young
    );

    let report = outcome
        .validate_gc_stress_boundary_minor_gc_live_object_bodies_and_generations()
        .expect("paired live body/generation writes validate");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    assert_eq!(
        report.body_write_report().payload_bytes(),
        write.destination_bytes().len()
    );
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("promoted destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                write.request(),
                ValueTag::Lambda
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

#[test]
fn live_object_body_generations_validate_unknown_destination_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let unchanged_destination_request = outcome
        .heap()
        .collector_poll_minor_gc_object_byte_copy_request_for_test(
            original_value,
            destination_value,
            MinorGcSurvivorAction::PromoteToOld,
        )
        .expect("test request for existing destination builds");
    let destination_generation_before = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");
    let missing_destination = static_gc_address(0x1000_0000);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(missing_destination, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with synthetic destination storage");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    assert_eq!(
        object_generation_plan.writes()[0].destination(),
        missing_destination
    );

    let err = outcome
        .validate_gc_stress_boundary_minor_gc_live_object_bodies_and_generations()
        .expect_err("synthetic destination body/generation validation remains unsupported");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectBodyDestination {
            destination: missing_destination,
        }
    );
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("unrelated destination remains heap-bound"),
        destination_generation_before
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                unchanged_destination_request,
                ValueTag::Lambda,
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == gc_address(destination_value)
    ));
}

#[test]
fn live_object_body_generations_bind_existing_copied_destination_record() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with an existing copied destination");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    let write = &object_generation_plan.writes()[0];
    assert_eq!(write.action(), MinorGcSurvivorAction::CopyToNursery);

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_bodies_and_generations()
        .expect("paired live body/generation writes copied destination");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.body_write_report().copied_to_nursery(), 1);
    assert_eq!(report.generation_write_report().copied_to_nursery(), 1);
    assert_eq!(
        report.body_write_report().payload_bytes(),
        write.destination_bytes().len()
    );
    assert!(outcome.value().raw_eq(original_value));
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(write.request(), ValueTag::Lambda)
        .expect("copied destination body is bound");
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("copied destination remains heap-bound"),
        HeapGeneration::Young
    );
}

#[test]
fn live_object_body_generations_bind_existing_promoted_destination_record() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), destination_address),
        )
        .expect("live metadata installs with an existing promoted destination");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    let write = &object_generation_plan.writes()[0];
    assert_eq!(write.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination starts heap-bound"),
        HeapGeneration::Young
    );

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_bodies_and_generations()
        .expect("paired live body/generation writes promoted destination");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    assert_eq!(
        report.body_write_report().payload_bytes(),
        write.destination_bytes().len()
    );
    assert!(outcome.value().raw_eq(original_value));
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(write.request(), ValueTag::Lambda)
        .expect("promoted destination body is bound");
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("promoted destination remains heap-bound"),
        HeapGeneration::Old
    );
}

#[test]
fn live_object_body_generations_reject_unknown_destination_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let unchanged_destination_request = outcome
        .heap()
        .collector_poll_minor_gc_object_byte_copy_request_for_test(
            original_value,
            destination_value,
            MinorGcSurvivorAction::PromoteToOld,
        )
        .expect("test request for existing destination builds");
    let destination_generation_before = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");
    let missing_destination = static_gc_address(0x1000_0000);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(missing_destination, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with synthetic destination storage");
    let object_generation_plan = outcome
        .gc_stress_boundary_minor_gc_object_generation_write_plan()
        .expect("object-generation write plan validates");
    assert_eq!(
        object_generation_plan.writes()[0].destination(),
        missing_destination
    );

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_object_bodies_and_generations()
        .expect_err("synthetic destination body/generation remains unsupported");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectBodyDestination {
            destination: missing_destination,
        }
    );
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("unrelated destination remains heap-bound"),
        destination_generation_before
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                unchanged_destination_request,
                ValueTag::Lambda,
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == gc_address(destination_value)
    ));
}

#[test]
fn outcome_root_writebacks_update_bound_value_stack_root() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);
    let old_base = static_gc_address(0x2000_0000);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, old_base),
        )
        .expect("live metadata installs with an already-bound destination");
    let object_byte_copy_plan = live_metadata
        .dry_run()
        .preflights()
        .worker()
        .expect("worker preflight records object copies")
        .object_byte_copy_plan()
        .clone();
    let body_report = outcome
        .heap
        .apply_collector_poll_minor_gc_object_body_writes(&object_byte_copy_plan)
        .expect("destination body writes apply");
    assert_eq!(live_metadata.reference_writebacks_installed(), 1);
    assert_eq!(body_report.objects(), 1);
    assert!(outcome.value().raw_eq(original_value));
    assert!(!outcome.value().raw_eq(destination_value));

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_outcome_root_writebacks()
        .expect("outcome value-stack root writeback applies");

    assert_eq!(report.value_stack_roots(), 1);
    assert_eq!(report.roots(), 1);
    assert!(outcome.value().raw_eq(destination_value));
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("destination value remains heap-bound"),
        HeapGeneration::Young
    );
}

#[test]
fn live_outcome_root_writebacks_bind_body_and_update_value_stack_root() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with an existing destination");
    assert_eq!(live_metadata.reference_writebacks_installed(), 1);
    let root_writeback_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_writeback = &root_writeback_plan.writes()[0];
    let request = root_writeback.request();
    assert!(matches!(
        outcome.heap().validate_collector_poll_minor_gc_object_body_binding(
            request,
            root_writeback.replacement_tag(),
        ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == destination_address
    ));
    assert!(outcome.value().raw_eq(original_value));

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_outcome_root_writebacks()
        .expect("live outcome root writeback binds body and rewrites value");

    assert_eq!(report.object_bodies_written(), 1);
    assert_eq!(report.object_body_write_report().objects(), 1);
    assert_eq!(
        report.object_body_write_report().payload_bytes(),
        root_writeback.destination_bytes().len()
    );
    assert_eq!(report.object_generations_written(), 1);
    assert_eq!(report.object_generation_write_report().objects(), 1);
    assert_eq!(
        report.object_generation_write_report().copied_to_nursery(),
        1
    );
    assert_eq!(report.value_stack_roots(), 1);
    assert_eq!(report.roots(), 1);
    assert!(outcome.value().raw_eq(destination_value));
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("destination value remains heap-bound"),
        HeapGeneration::Young
    );
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(
            request,
            root_writeback.replacement_tag(),
        )
        .expect("root replacement destination body is bound");
}

#[test]
fn live_outcome_root_writebacks_promote_destination_generation_and_update_value_stack_root() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), destination_address),
        )
        .expect("live metadata installs with an existing old destination");
    assert_eq!(live_metadata.reference_writebacks_installed(), 1);
    let root_writeback_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_writeback = &root_writeback_plan.writes()[0];
    assert_eq!(root_writeback.generation(), HeapGeneration::Old);
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination value starts heap-bound"),
        HeapGeneration::Young
    );
    assert!(outcome.value().raw_eq(original_value));

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_outcome_root_writebacks()
        .expect("live outcome root writeback promotes destination and rewrites value");

    assert_eq!(report.object_bodies_written(), 1);
    assert_eq!(report.object_generations_written(), 1);
    assert_eq!(report.object_generation_write_report().promoted_to_old(), 1);
    assert_eq!(report.value_stack_roots(), 1);
    assert!(outcome.value().raw_eq(destination_value));
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("destination value remains heap-bound"),
        HeapGeneration::Old
    );
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(
            root_writeback.request(),
            root_writeback.replacement_tag(),
        )
        .expect("root replacement destination body is bound");
}

#[test]
fn outcome_root_writebacks_reject_unbound_destination_body_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with an existing but unbound destination");
    assert!(outcome.value().raw_eq(original_value));

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_outcome_root_writebacks()
        .expect_err("unbound destination body is rejected");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        } if source_address == gc_address(original_value) && destination == destination_address
    ));
    assert!(outcome.value().raw_eq(original_value));
}

#[test]
fn outcome_root_writebacks_reject_stale_value_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);
    let stale_value = Value::int(1);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with an already-bound destination");
    assert!(outcome.value().raw_eq(original_value));
    outcome.value = stale_value;

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_outcome_root_writebacks()
        .expect_err("stale outcome value is rejected");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
            index: 0,
            expected_tag: ValueTag::Lambda,
            actual_tag: ValueTag::Int,
            ..
        }
    ));
    assert!(outcome.value().raw_eq(stale_value));
}

#[test]
fn live_outcome_root_writebacks_reject_stale_value_before_body_write() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let destination_address = gc_address(destination_value);
    let stale_value = Value::int(1);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs with an existing destination");
    let root_writeback_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_writeback = &root_writeback_plan.writes()[0];
    let request = root_writeback.request();
    let original_destination_generation = outcome
        .heap()
        .generation(destination_value)
        .expect("destination value is heap-bound");
    assert!(matches!(
        outcome.heap().validate_collector_poll_minor_gc_object_body_binding(
            request,
            root_writeback.replacement_tag(),
        ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == destination_address
    ));
    outcome.value = stale_value;

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_outcome_root_writebacks()
        .expect_err("stale outcome value is rejected before body writes");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
            index: 0,
            expected_tag: ValueTag::Lambda,
            actual_tag: ValueTag::Int,
            ..
        }
    ));
    assert!(outcome.value().raw_eq(stale_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination value remains heap-bound"),
        original_destination_generation
    );
    assert!(matches!(
        outcome.heap().validate_collector_poll_minor_gc_object_body_binding(
            request,
            root_writeback.replacement_tag(),
        ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(original_value) && destination == destination_address
    ));
}

#[test]
fn live_heap_field_writebacks_validate_direct_field_without_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_permanent_list_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for permanent direct field");
    let write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let write = &write_plan.writes()[0];
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("destination is heap-bound");
    let original_outcome_value = outcome.value();
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();

    let report = outcome
        .validate_gc_stress_boundary_minor_gc_live_heap_field_writebacks()
        .expect("live heap-field writeback preflight validates direct field");

    assert_eq!(report.object_body_preflight_objects(), 1);
    assert_eq!(report.object_generation_preflight_objects(), 1);
    assert_eq!(
        report.object_generation_write_report().copied_to_nursery(),
        1
    );
    assert_eq!(report.fields(), 1);
    assert_eq!(report.heap_field_writeback_report().fields(), 1);
    assert!(
        outcome
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .iter()
            .copied()
            .next()
            .expect("parent list has a child")
            .raw_eq(child)
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                write.replacement_request(),
                ValueTag::Lambda,
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert!(outcome.value().raw_eq(original_outcome_value));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_heap_field_writebacks_bind_replacement_generation_and_rewrite_direct_field() {
    let (mut outcome, parent, child, destination) =
        boundary_permanent_list_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for permanent direct field");
    assert_eq!(
        live_metadata.heap_field_writeback_destination_bindings_installed(),
        1
    );
    let write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let write = &write_plan.writes()[0];
    assert_eq!(write.writeback_object(), gc_address(parent));
    assert_eq!(write.replacement_request().source(), gc_address(child));
    assert_eq!(
        write.replacement_request().destination(),
        destination_address
    );
    assert!(matches!(
        outcome.heap().validate_collector_poll_minor_gc_object_body_binding(
            write.replacement_request(),
            ValueTag::Lambda,
        ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(child) && destination == destination_address
    ));

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_heap_field_writebacks()
        .expect("live heap-field writeback binds replacement and rewrites field");

    assert_eq!(report.object_bodies_written(), 1);
    assert_eq!(report.object_generations_written(), 1);
    assert_eq!(
        report.object_generation_write_report().copied_to_nursery(),
        1
    );
    assert_eq!(report.fields(), 1);
    assert_eq!(report.heap_field_writeback_report().fields(), 1);
    assert!(
        outcome
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .iter()
            .copied()
            .next()
            .expect("parent list has a child")
            .raw_eq(destination)
    );
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(
            write.replacement_request(),
            ValueTag::Lambda,
        )
        .expect("field replacement destination body is bound");
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination value remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(outcome.thunk_resolve_remembered_set().len(), 1);
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
}

#[test]
fn live_heap_field_writebacks_validate_rejects_stale_direct_field_without_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_permanent_list_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for permanent direct field");
    let write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let write = &write_plan.writes()[0];
    let original_request = write.replacement_request();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let stale_destination = outcome
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("stale destination lambda allocates");
    let stale_destination_address = gc_address(stale_destination);
    let stale_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(child),
        stale_destination_address,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        original_request.size_bytes(),
        original_request.align(),
    );
    let stale_body_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![stale_request]);
    outcome
        .heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&stale_body_plan)
        .expect("stale destination body/generation writes apply");
    let stale_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: stale_destination_address,
            generation: HeapGeneration::Young,
        },
        stale_request,
    );
    let (_, direct_report) = outcome
        .heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[stale_write],
            &mut outcome.thunk_resolve_remembered_set,
            &mut outcome.thunk_resolve_card_table,
        )
        .expect("test can stale the direct field");
    assert_eq!(direct_report.fields(), 1);
    let original_outcome_value = outcome.value();
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();

    let err = outcome
        .validate_gc_stress_boundary_minor_gc_live_heap_field_writebacks()
        .expect_err("stale direct field rejects live heap-field writeback preflight");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
            writeback_object,
            field_index: 0,
            field_source: HeapEdgeSource::ListElement { index: 0 },
            expected,
            actual,
        } if writeback_object == gc_address(parent)
            && expected == ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            }
            && actual == ResolvedValueGeneration::Heap {
                address: stale_destination_address,
                generation: HeapGeneration::Young,
            }
    ));
    assert!(
        outcome
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .iter()
            .copied()
            .next()
            .expect("parent list has a child")
            .raw_eq(stale_destination)
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(original_request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(child) && destination == destination_address
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
    assert!(outcome.value().raw_eq(original_outcome_value));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_heap_field_writebacks_reject_stale_direct_field_before_body_write() {
    let (mut outcome, parent, child, destination) =
        boundary_permanent_list_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for permanent direct field");
    let write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let write = &write_plan.writes()[0];
    let original_request = write.replacement_request();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let stale_destination = outcome
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("stale destination lambda allocates");
    let stale_destination_address = gc_address(stale_destination);
    let stale_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(child),
        stale_destination_address,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        original_request.size_bytes(),
        original_request.align(),
    );
    let stale_body_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![stale_request]);
    outcome
        .heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&stale_body_plan)
        .expect("stale destination body/generation writes apply");
    let stale_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: stale_destination_address,
            generation: HeapGeneration::Young,
        },
        stale_request,
    );
    let (_, direct_report) = outcome
        .heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[stale_write],
            &mut outcome.thunk_resolve_remembered_set,
            &mut outcome.thunk_resolve_card_table,
        )
        .expect("test can stale the direct field");
    assert_eq!(direct_report.fields(), 1);

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_heap_field_writebacks()
        .expect_err("stale direct field is rejected before body writes");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
            writeback_object,
            field_index: 0,
            field_source: HeapEdgeSource::ListElement { index: 0 },
            expected,
            actual,
        } if writeback_object == gc_address(parent)
            && expected == ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            }
            && actual == ResolvedValueGeneration::Heap {
                address: stale_destination_address,
                generation: HeapGeneration::Young,
            }
    ));
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(original_request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(child) && destination == destination_address
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
}

#[test]
fn live_reference_writebacks_validate_root_and_field_without_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for mixed root and field writebacks");
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();
    assert!(outcome.value().raw_eq(child));
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                root_write.request(),
                root_write.replacement_tag(),
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = outcome
        .validate_gc_stress_boundary_minor_gc_live_reference_writebacks()
        .expect("live reference writeback preflight validates root and field");

    assert_eq!(report.object_body_preflight_objects(), 1);
    assert_eq!(report.object_generation_preflight_objects(), 1);
    assert_eq!(report.roots(), 1);
    assert_eq!(report.fields(), 1);
    assert_eq!(report.references(), 2);
    assert!(outcome.value().raw_eq(child));
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(lambda.with_scope_env().scopes()[0].value().raw_eq(child));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                root_write.request(),
                root_write.replacement_tag(),
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_reference_writebacks_validate_rejects_stale_root_without_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);
    let stale_value = Value::int(1);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for mixed root and field writebacks");
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();
    outcome.value = stale_value;

    let err = outcome
        .validate_gc_stress_boundary_minor_gc_live_reference_writebacks()
        .expect_err("stale root rejects live reference writeback preflight");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
            index: 0,
            expected_tag: ValueTag::Lambda,
            actual_tag: ValueTag::Int,
            ..
        }
    ));
    assert!(outcome.value().raw_eq(stale_value));
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                root_write.request(),
                root_write.replacement_tag(),
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(lambda.with_scope_env().scopes()[0].value().raw_eq(child));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_existing_destination_commit_validate_headers_and_references_without_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("existing-destination live metadata installs for mixed writebacks");
    assert_eq!(
        live_metadata
            .live_metadata()
            .forwarding_pointers_installed(),
        1
    );
    assert_eq!(
        live_metadata
            .live_metadata()
            .forwarding_destination_bindings_installed(),
        1
    );
    assert_eq!(live_metadata.object_body_preflight_objects(), 1);
    assert_eq!(live_metadata.object_generation_preflight_objects(), 1);
    assert!(live_metadata.live_metadata().remembered_set_published());
    assert!(outcome.thunk_resolve_card_table().is_empty());
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let forwarding_before = outcome
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("source forwarding cell is readable");
    let original_outcome_value = outcome.value();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();

    let report = outcome
        .validate_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect("existing-destination live commit preflight validates");

    assert_eq!(report.forwarding_headers(), 1);
    assert_eq!(report.forwarding_headers_copied_to_nursery(), 1);
    assert_eq!(report.forwarding_headers_promoted_to_old(), 0);
    assert_eq!(
        report.forwarding_header_payload_bytes(),
        root_write.destination_bytes().len()
    );
    assert_eq!(report.object_body_preflight_objects(), 1);
    assert_eq!(report.object_generation_preflight_objects(), 1);
    assert_eq!(report.roots(), 1);
    assert_eq!(report.fields(), 1);
    assert_eq!(report.references(), 2);
    assert!(outcome.value().raw_eq(original_outcome_value));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("source forwarding cell remains readable"),
        forwarding_before
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                root_write.request(),
                root_write.replacement_tag(),
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_existing_destination_commit_validate_rejects_missing_forwarding_without_mutation() {
    let (mut outcome, original_value, destination_value) =
        boundary_lambda_outcome_with_existing_destination();
    let original_address = gc_address(original_value);
    let destination_address = gc_address(destination_value);

    let forwarding_binding_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("forwarding-destination binding metadata installs");
    assert_eq!(
        forwarding_binding_dry_run.forwarding_destination_bindings_installed(),
        1
    );
    let forwarding_destination_bindings_before = outcome
        .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
        .clone();
    let original_destination_generation = outcome
        .heap()
        .generation(destination_value)
        .expect("destination starts heap-bound");

    let err = outcome
        .validate_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("missing live forwarding cell rejects commit preflight");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingHeaderWriteMissingForwarding {
            source_address,
            expected
        } if source_address == original_address
            && expected == ResolvedValueGeneration::Heap {
                address: destination_address,
                generation: HeapGeneration::Young,
            }
    ));
    assert!(outcome.value().raw_eq(original_value));
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("source forwarding cell remains readable"),
        None
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata(),
        &forwarding_destination_bindings_before
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
}

#[test]
fn live_existing_destination_commit_validate_rejects_reference_only_metadata_first() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    let reference_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("reference writeback metadata installs without forwarding headers");
    assert_eq!(reference_dry_run.reference_writebacks_installed(), 2);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
            .is_empty()
    );
    let stale_value = Value::int(1);
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();
    outcome.value = stale_value;

    let err = outcome
        .validate_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("reference-only metadata rejects before stale root validation");

    assert_eq!(
        err,
        EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingForwardingHeaders {
            references: 2,
            forwarding_headers: 0,
        }
    );
    assert!(outcome.value().raw_eq(stale_value));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_existing_destination_commit_applies_references_after_header_validation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("existing-destination live metadata installs for mixed writebacks");
    assert_eq!(
        live_metadata
            .live_metadata()
            .forwarding_pointers_installed(),
        1
    );
    assert_eq!(live_metadata.object_body_preflight_objects(), 1);
    assert_eq!(live_metadata.object_generation_preflight_objects(), 1);
    assert!(live_metadata.live_metadata().remembered_set_published());
    assert!(outcome.thunk_resolve_card_table().is_empty());
    let published_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let forwarding_before = outcome
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("source forwarding cell is readable");

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect("existing-destination live commit applies after forwarding validation");

    assert_eq!(report.forwarding_headers_validated(), 1);
    assert_eq!(report.forwarding_headers_copied_to_nursery(), 1);
    assert_eq!(report.forwarding_headers_promoted_to_old(), 0);
    assert_eq!(
        report.forwarding_header_payload_bytes(),
        root_write.destination_bytes().len()
    );
    assert_eq!(report.object_bodies_written(), 1);
    assert_eq!(report.object_generations_written(), 1);
    assert_eq!(report.value_stack_roots(), 1);
    assert_eq!(report.roots(), 1);
    assert_eq!(report.fields(), 1);
    assert_eq!(report.references(), 2);
    assert_eq!(
        report.remembered_set_published_edges(),
        published_remembered_edges.len()
    );
    assert_eq!(report.card_table_dirty_cards_cleared(), 1);
    assert!(outcome.value().raw_eq(destination));
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(destination)
    );
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(
            root_write.request(),
            root_write.replacement_tag(),
        )
        .expect("shared existing destination body is bound");
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("source forwarding cell remains readable"),
        forwarding_before
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        published_remembered_edges.as_slice()
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn existing_destination_live_commit_runs_metadata_and_reference_commit() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);

    let commit = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_commit(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("composed existing-destination live commit applies");

    assert_eq!(commit.forwarding_pointers_installed(), 1);
    assert_eq!(commit.object_bodies_written(), 1);
    assert_eq!(commit.object_generations_written(), 1);
    assert_eq!(commit.value_stack_roots(), 1);
    assert_eq!(commit.fields(), 1);
    assert_eq!(commit.references(), 2);
    assert_eq!(commit.card_table_dirty_cards_cleared(), 1);
    assert_eq!(commit.live_metadata().object_body_preflight_objects(), 1);
    assert_eq!(
        commit.live_metadata().object_generation_preflight_objects(),
        1
    );
    assert_eq!(commit.live_commit().forwarding_headers_validated(), 1);
    assert!(
        commit
            .live_metadata()
            .live_metadata()
            .remembered_set_published()
    );
    assert!(outcome.value().raw_eq(destination));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(destination)
    );
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan still validates after commit");
    let root_write = &root_plan.writes()[0];
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(
            root_write.request(),
            root_write.replacement_tag(),
        )
        .expect("existing destination body is bound");
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("source forwarding cell remains readable"),
        Some(ResolvedValueGeneration::Heap {
            address: destination_address,
            generation: HeapGeneration::Young,
        })
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn live_existing_destination_commit_apply_rejects_dirty_card_table_before_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("existing-destination live metadata installs for mixed writebacks");
    assert!(outcome.thunk_resolve_card_table().is_empty());
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let forwarding_before = outcome
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("source forwarding cell is readable");
    let original_outcome_value = outcome.value();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let dirty_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(dirty_source)
        .expect("stale dirty card marks");

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("dirty card table rejects before existing-destination commit");

    assert_eq!(
        err,
        EvalHeapError::BoundaryMinorGcExistingDestinationCommitDirtyCardTable { dirty_cards: 1 }
    );
    assert!(outcome.value().raw_eq(original_outcome_value));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("source forwarding cell remains readable"),
        forwarding_before
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                root_write.request(),
                root_write.replacement_tag(),
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards()[0].source(),
        dirty_source
    );
}

#[test]
fn live_existing_destination_commit_rejects_superset_published_remembered_set_before_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let source_address = gc_address(child);
    let writeback_source = gc_address(parent);
    let destination_address = gc_address(destination);
    let expected_edge = RememberedEdge::new(writeback_source, destination_address);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("existing-destination live metadata installs for mixed writebacks");
    assert!(outcome.thunk_resolve_card_table().is_empty());
    assert!(
        outcome
            .thunk_resolve_remembered_set()
            .edges()
            .contains(&expected_edge)
    );
    let expected_epoch = outcome.thunk_resolve_remembered_set().epoch();
    let expected_edges = outcome.thunk_resolve_remembered_set().len();
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let forwarding_before = outcome
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("source forwarding cell is readable");
    let original_outcome_value = outcome.value();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let stale_edge = RememberedEdge::new(writeback_source, static_gc_address(0x3000_0000));
    let mut stale_remembered_set = RememberedSet::with_epoch(expected_epoch);
    stale_remembered_set
        .record(expected_edge)
        .expect("expected remembered edge records in stale superset");
    stale_remembered_set
        .record(stale_edge)
        .expect("stale remembered edge records");
    outcome.thunk_resolve_remembered_set = stale_remembered_set;

    let validate_err = outcome
        .validate_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("stale remembered set rejects existing-destination preflight");
    assert_eq!(
        validate_err,
        EvalHeapError::BoundaryMinorGcExistingDestinationCommitRememberedSetPublicationMismatch {
            expected_epoch,
            actual_epoch: expected_epoch,
            expected_edges,
            actual_edges: 2,
        }
    );
    let apply_err = outcome
        .apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("stale remembered set rejects before existing-destination commit");

    assert_eq!(
        apply_err,
        EvalHeapError::BoundaryMinorGcExistingDestinationCommitRememberedSetPublicationMismatch {
            expected_epoch,
            actual_epoch: expected_epoch,
            expected_edges,
            actual_edges: 2,
        }
    );
    assert!(outcome.value().raw_eq(original_outcome_value));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("source forwarding cell remains readable"),
        forwarding_before
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                root_write.request(),
                root_write.replacement_tag(),
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        &[expected_edge, stale_edge]
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn live_existing_destination_commit_apply_rejects_reference_only_metadata_first() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    let reference_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("reference writeback metadata installs without forwarding headers");
    assert_eq!(reference_dry_run.reference_writebacks_installed(), 2);
    let stale_value = Value::int(1);
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();
    outcome.value = stale_value;

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("reference-only metadata rejects before stale root validation");

    assert_eq!(
        err,
        EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingForwardingHeaders {
            references: 2,
            forwarding_headers: 0,
        }
    );
    assert!(outcome.value().raw_eq(stale_value));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_existing_destination_commit_apply_rejects_stale_forwarding_before_reference_mutation() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let source_address = gc_address(child);
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("forwarding destination metadata installs");
    let reference_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("reference writeback metadata installs");
    assert_eq!(reference_dry_run.reference_writebacks_installed(), 2);
    let forwarding_binding = outcome
        .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
        .forwarding_destination_bindings()[0]
        .clone();
    let stale_forwarded_value = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x3000_0000),
        generation: HeapGeneration::Young,
    };
    outcome
        .heap
        .install_collector_poll_minor_gc_forwarding_slots(&[
            MinorGcForwardingSlot::with_forwarded_value(source_address, stale_forwarded_value),
        ])
        .expect("stale forwarding value installs");
    let stale_value = Value::int(1);
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();
    outcome.value = stale_value;

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()
        .expect_err("stale forwarding rejects before stale root validation");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingHeaderWriteForwardingMismatch {
            source_address: actual_source,
            expected,
            actual
        } if actual_source == source_address
            && actual_source == forwarding_binding.source()
            && expected == forwarding_binding.forwarded_value()
            && actual == stale_forwarded_value
    ));
    assert!(outcome.value().raw_eq(stale_value));
    assert!(
        outcome
            .heap()
            .get_lambda(parent)
            .expect("parent lambda remains typed")
            .with_scope_env()
            .scopes()[0]
            .value()
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("source forwarding cell remains readable"),
        Some(stale_forwarded_value)
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_reference_writebacks_bind_once_and_rewrite_root_and_direct_field() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    let live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for mixed root and field writebacks");
    assert_eq!(
        live_metadata.root_writeback_destination_bindings_installed(),
        1
    );
    assert_eq!(
        live_metadata.heap_field_writeback_destination_bindings_installed(),
        1
    );
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let heap_field_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    assert_eq!(root_plan.len(), 1);
    assert_eq!(heap_field_plan.len(), 1);
    let root_write = &root_plan.writes()[0];
    let field_write = &heap_field_plan.writes()[0];
    assert_eq!(root_write.request().source(), gc_address(child));
    assert_eq!(root_write.request().destination(), destination_address);
    assert_eq!(field_write.writeback_object(), gc_address(parent));
    assert_eq!(
        field_write.replacement_request().source(),
        gc_address(child)
    );
    assert_eq!(
        field_write.replacement_request().destination(),
        destination_address
    );
    assert!(outcome.value().raw_eq(child));

    let report = outcome
        .apply_gc_stress_boundary_minor_gc_live_reference_writebacks()
        .expect("live reference writeback binds once and rewrites root plus field");

    assert_eq!(report.object_bodies_written(), 1);
    assert_eq!(report.object_generations_written(), 1);
    assert_eq!(report.roots(), 1);
    assert_eq!(report.fields(), 1);
    assert_eq!(report.references(), 2);
    assert!(outcome.value().raw_eq(destination));
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(destination)
    );
    outcome
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(
            root_write.request(),
            ValueTag::Lambda,
        )
        .expect("shared replacement destination body is bound");
    assert_eq!(outcome.thunk_resolve_remembered_set().len(), 1);
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
}

#[test]
fn live_reference_writebacks_reject_stale_root_before_field_or_body_write() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);
    let stale_value = Value::int(1);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for mixed root and field writebacks");
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let root_write = &root_plan.writes()[0];
    let root_request = root_write.request();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let original_remembered_edges = outcome.thunk_resolve_remembered_set().edges().to_vec();
    let original_dirty_cards = outcome.thunk_resolve_card_table().dirty_cards().to_vec();
    assert!(matches!(
        outcome.heap().validate_collector_poll_minor_gc_object_body_binding(
            root_request,
            root_write.replacement_tag(),
        ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(child) && destination == destination_address
    ));
    outcome.value = stale_value;

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_reference_writebacks()
        .expect_err("stale root rejects combined live reference writeback");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
            index: 0,
            expected_tag: ValueTag::Lambda,
            actual_tag: ValueTag::Int,
            ..
        }
    ));
    assert!(outcome.value().raw_eq(stale_value));
    assert!(matches!(
        outcome.heap().validate_collector_poll_minor_gc_object_body_binding(
            root_request,
            root_write.replacement_tag(),
        ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(child) && destination == destination_address
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(lambda.with_scope_env().scopes()[0].value().raw_eq(child));
    assert_eq!(
        outcome.thunk_resolve_remembered_set().edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

#[test]
fn live_reference_writebacks_reject_stale_field_before_root_or_body_write() {
    let (mut outcome, parent, child, destination) =
        boundary_root_and_permanent_lambda_field_outcome_with_existing_destination();
    let destination_address = gc_address(destination);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata installs for mixed root and field writebacks");
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    let original_root_request = root_plan.writes()[0].request();
    let original_destination_generation = outcome
        .heap()
        .generation(destination)
        .expect("original destination is heap-bound");
    let heap_field_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let field_write = heap_field_plan.writes()[0].clone();
    let original_field_request = field_write.replacement_request();
    let stale_destination = outcome
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("stale destination lambda allocates");
    let stale_destination_address = gc_address(stale_destination);
    let stale_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(child),
        stale_destination_address,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        original_field_request.size_bytes(),
        original_field_request.align(),
    );
    let stale_body_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![stale_request]);
    outcome
        .heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&stale_body_plan)
        .expect("stale destination body/generation writes apply");
    let stale_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        field_write.allocation_domain(),
        field_write.writeback_object(),
        field_write.field_index(),
        field_write.source().clone(),
        ResolvedValueGeneration::Heap {
            address: stale_destination_address,
            generation: HeapGeneration::Young,
        },
        stale_request,
    );
    let (_, direct_report) = outcome
        .heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[stale_write],
            &mut outcome.thunk_resolve_remembered_set,
            &mut outcome.thunk_resolve_card_table,
        )
        .expect("test can stale the direct field");
    assert_eq!(direct_report.fields(), 1);

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_reference_writebacks()
        .expect_err("stale field rejects combined live reference writeback");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
            writeback_object,
            field_index,
            expected,
            actual,
            ..
        } if writeback_object == gc_address(parent)
            && field_index == field_write.field_index()
            && expected == ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            }
            && actual == ResolvedValueGeneration::Heap {
                address: stale_destination_address,
                generation: HeapGeneration::Young,
            }
    ));
    assert!(outcome.value().raw_eq(child));
    assert!(matches!(
        outcome
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(
                original_root_request,
                ValueTag::Lambda,
            ),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            source_address,
            destination,
            reason: "destination record body does not match source record body",
        }) if source_address == gc_address(child) && destination == destination_address
    ));
    assert_eq!(
        outcome
            .heap()
            .generation(destination)
            .expect("original destination remains heap-bound"),
        original_destination_generation
    );
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(stale_destination)
    );
}

#[test]
fn live_heap_field_writebacks_reject_direct_writeback_destination_alias_before_mutation() {
    let (mut outcome, parent, child, _destination) =
        boundary_permanent_list_field_outcome_with_existing_destination();
    let parent_address = gc_address(parent);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(parent_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata can describe an aliased direct heap-field destination");
    let heap_field_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let field_write = &heap_field_plan.writes()[0];
    assert_eq!(field_write.writeback_object(), parent_address);
    assert_eq!(
        field_write.replacement_request().destination(),
        parent_address
    );

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_heap_field_writebacks()
        .expect_err("direct writeback owner cannot also be a field replacement destination");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcLiveReferenceWritebackDestinationAliasesDirectWriteback {
            allocation_domain: HeapAllocationDomain::PermanentShared,
            writeback_object,
            field_index,
            destination,
            ..
        } if writeback_object == parent_address
            && field_index == field_write.field_index()
            && destination == parent_address
    ));
    assert!(outcome.value().raw_eq(parent));
    assert!(
        outcome
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .iter()
            .copied()
            .next()
            .expect("parent list has child")
            .raw_eq(child)
    );
    assert_eq!(
        outcome
            .heap()
            .generation(parent)
            .expect("parent remains heap-bound"),
        HeapGeneration::Permanent
    );
}

#[test]
fn live_reference_writebacks_reject_direct_writeback_destination_alias_before_mutation() {
    let (mut outcome, parent, root_child, field_child) =
        boundary_distinct_root_and_permanent_lambda_field_outcome();
    let parent_address = gc_address(parent);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(parent_address, static_gc_address(0x2000_0000)),
        )
        .expect("live metadata can describe an aliased direct writeback destination");
    let root_plan = outcome
        .gc_stress_boundary_minor_gc_root_writeback_write_plan()
        .expect("root writeback plan validates");
    assert_eq!(
        root_plan.writes()[0].request().source(),
        gc_address(root_child)
    );
    assert_eq!(
        root_plan.writes()[0].request().destination(),
        parent_address
    );
    let heap_field_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback plan validates");
    let field_write = &heap_field_plan.writes()[0];
    assert_eq!(field_write.writeback_object(), parent_address);
    assert_eq!(
        field_write.replacement_request().source(),
        gc_address(field_child)
    );
    assert_ne!(
        field_write.replacement_request().destination(),
        parent_address
    );

    let err = outcome
        .apply_gc_stress_boundary_minor_gc_live_reference_writebacks()
        .expect_err("direct writeback owner cannot also be an object-copy destination");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcLiveReferenceWritebackDestinationAliasesDirectWriteback {
            allocation_domain: HeapAllocationDomain::PermanentShared,
            writeback_object,
            field_index,
            destination,
            ..
        } if writeback_object == parent_address
            && field_index == field_write.field_index()
            && destination == parent_address
    ));
    assert!(outcome.value().raw_eq(root_child));
    assert_eq!(
        outcome
            .heap()
            .generation(parent)
            .expect("parent remains heap-bound"),
        HeapGeneration::Permanent
    );
    let lambda = outcome
        .heap()
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(field_child)
    );
}

#[test]
fn forwarding_destination_bindings_reject_extra_installed_forwarding_cell() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for forwarding binding validation");
    let nursery_base = static_gc_address(0x1000_0000);
    let old_base = static_gc_address(0x2000_0000);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("single-tier worker dry-run installs coherent live metadata");
    let extra_source = outcome
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(99)))
        .expect("extra young source allocates");
    let extra_source_address = gc_address(extra_source);
    outcome
        .heap
        .install_collector_poll_minor_gc_forwarding_slots(&[
            MinorGcForwardingSlot::with_forwarded_value(
                extra_source_address,
                ResolvedValueGeneration::Heap {
                    address: static_gc_address(0x3000_0000),
                    generation: HeapGeneration::Young,
                },
            ),
        ])
        .expect("extra forwarding cell installs");

    let err = outcome
        .gc_stress_boundary_minor_gc_forwarding_destination_bindings()
        .expect_err("extra forwarding cell without destination storage is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingDestinationMissing { source_address }
            if source_address == extra_source_address
    ));
    let header_plan_error = outcome
        .gc_stress_boundary_minor_gc_forwarding_header_write_plan()
        .expect_err("extra forwarding cell without a binding rejects header planning");
    assert!(matches!(
        header_plan_error,
        EvalHeapError::BoundaryMinorGcForwardingHeaderWriteUnboundForwarding {
            source_address,
            actual
        } if source_address == extra_source_address
                && actual == (ResolvedValueGeneration::Heap {
                    address: static_gc_address(0x3000_0000),
                    generation: HeapGeneration::Young,
                })
    ));
}

#[test]
fn live_metadata_rejects_preexisting_extra_forwarding_cell_before_mutation() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let root = evaluator.eval_root().expect("lambda evaluates");
    let root_address = gc_address(root);
    let extra_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(99)))
        .expect("extra young source allocates before boundary scan");
    let extra_source_address = gc_address(extra_source);
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(root)
        .expect("boundary scan captures post-extra-allocation heap state");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let mut outcome = EvalOutcome {
        value: root,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
        thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
        memory_budget_action: None,
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans,
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
    };
    outcome
        .heap
        .install_collector_poll_minor_gc_forwarding_slots(&[
            MinorGcForwardingSlot::with_forwarded_value(
                extra_source_address,
                ResolvedValueGeneration::Heap {
                    address: static_gc_address(0x3000_0000),
                    generation: HeapGeneration::Young,
                },
            ),
        ])
        .expect("preexisting extra forwarding cell installs");

    let err = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect_err("extra forwarding cell rejects all-in-one metadata preflight");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingDestinationMissing { source_address }
            if source_address == extra_source_address
    ));
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_object_generations()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    assert_eq!(outcome.thunk_resolve_remembered_set().len(), 0);
    assert_eq!(outcome.thunk_resolve_card_table().len(), 0);
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(root_address)
            .expect("planned forwarding source remains known"),
        None
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(extra_source_address)
            .expect("extra forwarding source remains known"),
        Some(ResolvedValueGeneration::Heap {
            address: static_gc_address(0x3000_0000),
            generation: HeapGeneration::Young,
        })
    );
}

#[test]
fn live_metadata_empty_boundary_accepts_preinstalled_forwarding_destination_metadata() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for empty-boundary validation");
    let original_value = outcome.value();
    let original_address = gc_address(original_value);
    let nursery_base = static_gc_address(0x1000_0000);
    let old_base = static_gc_address(0x2000_0000);

    outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("initial metadata install succeeds");
    let destination_storage_before = outcome
        .gc_stress_boundary_minor_gc_destination_storage()
        .clone();
    let forwarding_destination_bindings_before = outcome
        .gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata()
        .clone();
    let object_generations_before = outcome
        .gc_stress_boundary_minor_gc_object_generations()
        .clone();
    let writebacks_before = outcome
        .gc_stress_boundary_minor_gc_reference_writebacks()
        .clone();
    let writeback_destination_bindings_before = outcome
        .gc_stress_boundary_minor_gc_writeback_destination_bindings()
        .clone();
    let remembered_epoch_before = outcome.thunk_resolve_remembered_set().epoch();
    let remembered_edges_before = outcome.thunk_resolve_remembered_set().len();
    let card_table_dirty_before = outcome.thunk_resolve_card_table().len();
    outcome.gc_stress_boundary_scans = EvalGcStressBoundaryScans::default();

    let empty_live_metadata = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("empty boundary validates existing coherent metadata");

    assert_eq!(empty_live_metadata.forwarding_pointers_installed(), 0);
    assert_eq!(
        empty_live_metadata.forwarding_destination_bindings_installed(),
        0
    );
    assert_eq!(empty_live_metadata.object_copies_installed(), 0);
    assert_eq!(empty_live_metadata.object_generations_installed(), 0);
    assert_eq!(empty_live_metadata.reference_writebacks_installed(), 0);
    assert_eq!(
        empty_live_metadata.writeback_destination_bindings_installed(),
        0
    );
    assert!(!empty_live_metadata.remembered_set_published());
    assert_eq!(empty_live_metadata.card_table_dirty_cards_cleared(), 0);
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_destination_storage(),
        &destination_storage_before
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata(),
        &forwarding_destination_bindings_before
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_object_generations(),
        &object_generations_before
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_reference_writebacks(),
        &writebacks_before
    );
    assert_eq!(
        outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings(),
        &writeback_destination_bindings_before
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set().epoch(),
        remembered_epoch_before
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set().len(),
        remembered_edges_before
    );
    assert_eq!(
        outcome.thunk_resolve_card_table().len(),
        card_table_dirty_before
    );
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(original_address)
            .expect("existing forwarding source remains known"),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_destination_bindings()
            .expect("retained forwarding destination bindings still validate")
            .len(),
        1
    );
}

#[test]
fn owned_eval_reports_gc_stress_boundary_promoted_commit_dry_run_bytes() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let old_base = static_gc_address(0x2000_0000);

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), old_base),
        )
        .expect("boundary scan runs promoted owned commit dry-run");

    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.object_copies(), 1);
    assert_eq!(summary.copied_to_nursery(), 0);
    assert_eq!(summary.promoted_to_old(), 1);
    assert!(summary.object_copy_bytes() > 0);
    assert_eq!(summary.copy_to_nursery_bytes(), 0);
    assert_eq!(summary.object_copy_bytes(), summary.promote_to_old_bytes());

    let preflight = dry_run
        .preflights()
        .worker()
        .expect("worker promoted dry-run preflight records");
    assert_eq!(preflight.copy_to_nursery_bytes(), 0);
    assert_eq!(
        summary.promote_to_old_bytes(),
        preflight.promote_to_old_bytes()
    );
    let commit_application = dry_run
        .commit_applications()
        .worker()
        .expect("worker promoted dry-run commit records");
    assert_eq!(commit_application.report().copied_to_nursery(), 0);
    assert_eq!(commit_application.report().promoted_to_old(), 1);
    let object_copy = &commit_application.object_byte_copies()[0];
    let destination_storage = commit_application.destination_storage();
    assert_eq!(destination_storage.copy_report().copied_to_nursery(), 0);
    assert_eq!(destination_storage.copy_report().promoted_to_old(), 1);
    assert_eq!(destination_storage.nursery_reserved_bytes(), 0);
    assert_eq!(
        destination_storage.old_reserved_bytes(),
        preflight
            .relocation_plan()
            .relocation_destinations()
            .placement_plan()
            .old_reserved_bytes()
    );
    assert!(destination_storage.nursery_destination_bytes().is_empty());
    assert_eq!(
        destination_storage.old_destination_bytes(),
        object_copy.source_bytes()
    );
    assert_eq!(
        commit_application.forwarding_slots()[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        })
    );
    assert_eq!(
        commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        }]
    );
    let owned_storage_application = preflight
        .apply_commit_to_owned_destination_storage()
        .expect("promoted boundary preflight applies owned destination storage commit");
    assert_eq!(owned_storage_application.report().copied_to_nursery(), 0);
    assert_eq!(owned_storage_application.report().promoted_to_old(), 1);
    let owned_destination_storage = owned_storage_application.destination_storage();
    assert_eq!(
        owned_destination_storage.copy_report().copied_to_nursery(),
        0
    );
    assert_eq!(owned_destination_storage.copy_report().promoted_to_old(), 1);
    assert_eq!(owned_destination_storage.nursery_reserved_bytes(), 0);
    assert_eq!(
        owned_destination_storage.old_reserved_bytes(),
        destination_storage.old_reserved_bytes()
    );
    assert!(
        owned_destination_storage
            .nursery_destination_bytes()
            .is_empty()
    );
    assert_eq!(
        owned_destination_storage.old_destination_bytes(),
        object_copy.source_bytes()
    );
    let owned_forwarded_value = owned_storage_application.forwarding_slots()[0]
        .forwarded_value()
        .expect("promoted owned-storage commit installs forwarding");
    let ResolvedValueGeneration::Heap {
        address: owned_old_base,
        generation: HeapGeneration::Old,
    } = owned_forwarded_value
    else {
        panic!("promoted owned-storage survivor remains old");
    };
    assert_eq!(
        owned_storage_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: owned_old_base,
            generation: HeapGeneration::Old,
        }]
    );
    assert!(owned_storage_application.remembered_set().is_empty());
    assert!(owned_storage_application.card_table().is_empty());
    let dry_run_owned_storage_application = dry_run
        .owned_storage_commit_applications()
        .worker()
        .expect("promoted dry-run owned-storage commit records");
    assert_eq!(
        dry_run_owned_storage_application.report(),
        owned_storage_application.report()
    );
    assert_eq!(
        dry_run_owned_storage_application
            .destination_storage()
            .copy_report(),
        owned_destination_storage.copy_report()
    );
    assert!(
        dry_run_owned_storage_application
            .destination_storage()
            .nursery_destination_bytes()
            .is_empty()
    );
    assert_eq!(
        dry_run_owned_storage_application
            .destination_storage()
            .old_destination_bytes(),
        object_copy.source_bytes()
    );
    let dry_run_owned_forwarded_value = dry_run_owned_storage_application.forwarding_slots()[0]
        .forwarded_value()
        .expect("promoted dry-run owned-storage commit installs forwarding");
    let ResolvedValueGeneration::Heap {
        address: dry_run_owned_old_base,
        generation: HeapGeneration::Old,
    } = dry_run_owned_forwarded_value
    else {
        panic!("promoted dry-run owned-storage survivor remains old");
    };
    assert_eq!(
        dry_run_owned_storage_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: dry_run_owned_old_base,
            generation: HeapGeneration::Old,
        }]
    );
    assert!(
        dry_run_owned_storage_application
            .remembered_set()
            .is_empty()
    );
    assert!(dry_run_owned_storage_application.card_table().is_empty());

    let mut destination_outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress for promoted destination storage");
    let live_destination_dry_run = destination_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), old_base),
        )
        .expect("promoted worker dry-run installs live destination bytes");
    let live_destination_commit = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live promoted destination worker commit records");
    let live_destination_object_copy = &live_destination_commit.object_byte_copies()[0];
    let live_destination_storage =
        destination_outcome.gc_stress_boundary_minor_gc_destination_storage();
    assert_eq!(live_destination_dry_run.object_copies_installed(), 1);
    assert_eq!(
        live_destination_dry_run
            .destination_storage_install_report()
            .promoted_to_old(),
        1
    );
    assert_eq!(
        live_destination_dry_run
            .destination_storage_install_report()
            .old_payload_bytes(),
        live_destination_object_copy.request().size_bytes()
    );
    assert_eq!(live_destination_storage.len(), 1);
    assert_eq!(
        live_destination_storage.object_bytes()[0].request(),
        live_destination_object_copy.request()
    );
    assert_eq!(
        live_destination_storage.object_bytes()[0].destination_bytes(),
        live_destination_object_copy.destination_bytes()
    );

    let live_forwarding_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), old_base),
        )
        .expect("promoted worker dry-run installs live forwarding");
    let live_forwarding_slot = live_forwarding_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live promoted worker commit records")
        .forwarding_slots()[0];
    assert_eq!(live_forwarding_dry_run.forwarding_pointers_installed(), 1);
    assert_eq!(
        outcome
            .heap()
            .minor_gc_forwarding_value_at(live_forwarding_slot.source())
            .expect("promoted forwarding source remains known"),
        Some(ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        })
    );
}

#[test]
fn owned_eval_runs_gc_stress_boundary_permanent_commit_dry_run() {
    let ir = lower("\"stress\"");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan runs owned commit dry-run");

    assert_eq!(dry_run.len(), 1);
    assert!(!dry_run.is_empty());
    assert!(dry_run.preflights().worker().is_none());
    assert!(dry_run.reference_writebacks().worker().is_none());
    assert!(dry_run.commit_applications().worker().is_none());
    assert!(
        dry_run
            .owned_storage_commit_applications()
            .worker()
            .is_none()
    );
    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.object_copies(), 0);
    assert_eq!(summary.copied_to_nursery(), 0);
    assert_eq!(summary.promoted_to_old(), 0);
    assert_eq!(summary.object_copy_bytes(), 0);
    assert_eq!(summary.copy_to_nursery_bytes(), 0);
    assert_eq!(summary.promote_to_old_bytes(), 0);
    assert_eq!(summary.forwarding_pointers(), 0);
    assert_eq!(summary.reference_rewrites(), 0);
    assert_eq!(summary.root_writebacks(), 0);
    assert_eq!(summary.heap_field_writebacks(), 0);
    assert_eq!(summary.reference_writebacks(), 0);
    assert_eq!(summary.remembered_set_source_edges(), 0);
    assert_eq!(summary.remembered_set_published_edges(), 0);

    let preflight = dry_run
        .preflights()
        .permanent_shared()
        .expect("permanent dry-run preflight records");
    let writeback_application = dry_run
        .reference_writebacks()
        .permanent_shared()
        .expect("permanent dry-run writebacks record");
    let commit_application = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent dry-run commit records");

    assert!(preflight.object_byte_copy_plan().is_empty());
    assert!(preflight.forwarding_slots().is_empty());
    assert!(preflight.reference_writeback_plan().is_empty());
    assert_eq!(writeback_application.report().writebacks(), 0);
    assert!(writeback_application.root_writeback_slots().is_empty());
    assert!(
        writeback_application
            .heap_field_writeback_slots()
            .is_empty()
    );

    let commit_report = commit_application.report();
    assert_eq!(commit_report.object_copies(), 0);
    assert_eq!(commit_report.forwarding_pointers(), 0);
    assert_eq!(commit_report.reference_rewrites(), 0);
    assert!(commit_application.object_byte_copies().is_empty());
    assert_eq!(
        commit_application
            .destination_storage()
            .copy_report()
            .object_copies(),
        0
    );
    assert_eq!(
        commit_application
            .destination_storage()
            .nursery_reserved_bytes(),
        0
    );
    assert_eq!(
        commit_application
            .destination_storage()
            .old_reserved_bytes(),
        0
    );
    assert!(
        commit_application
            .destination_storage()
            .nursery_destination_bytes()
            .is_empty()
    );
    assert!(
        commit_application
            .destination_storage()
            .old_destination_bytes()
            .is_empty()
    );
    assert!(commit_application.forwarding_slots().is_empty());
    assert_eq!(
        commit_application.references(),
        preflight.reference_buffer()
    );
    assert!(commit_application.references().iter().all(|value| matches!(
        value,
        ResolvedValueGeneration::Heap {
            generation: HeapGeneration::Permanent,
            ..
        }
    )));
    assert!(commit_application.remembered_set().is_empty());
    let owned_storage_commit_application = dry_run
        .owned_storage_commit_applications()
        .permanent_shared()
        .expect("permanent dry-run owned-storage commit records");
    assert_eq!(owned_storage_commit_application.report(), commit_report);
    assert_eq!(
        owned_storage_commit_application
            .destination_storage()
            .copy_report()
            .object_copies(),
        0
    );
    assert_eq!(
        owned_storage_commit_application
            .destination_storage()
            .nursery_reserved_bytes(),
        0
    );
    assert_eq!(
        owned_storage_commit_application
            .destination_storage()
            .old_reserved_bytes(),
        0
    );
    assert!(
        owned_storage_commit_application
            .destination_storage()
            .nursery_destination_bytes()
            .is_empty()
    );
    assert!(
        owned_storage_commit_application
            .destination_storage()
            .old_destination_bytes()
            .is_empty()
    );
    assert!(
        owned_storage_commit_application
            .forwarding_slots()
            .is_empty()
    );
    assert_eq!(
        owned_storage_commit_application.references(),
        preflight.reference_buffer()
    );
    assert!(owned_storage_commit_application.remembered_set().is_empty());
    assert!(owned_storage_commit_application.card_table().is_empty());

    let live_dirty_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(live_dirty_source)
        .expect("permanent single-tier live dirty card marks");
    let live_state_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("single-tier permanent dry-run publishes live remembered set");
    assert!(
        live_state_dry_run
            .dry_run()
            .commit_applications()
            .worker()
            .is_none()
    );
    let live_permanent_commit = live_state_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live permanent commit records");
    assert!(live_state_dry_run.remembered_set_published());
    assert_eq!(live_state_dry_run.card_table_dirty_cards_cleared(), 1);
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        live_permanent_commit.remembered_set()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 0);
}

#[test]
fn owned_eval_reports_gc_stress_boundary_heap_field_writeback_slots() {
    let ir = lower("let captured = x: x; in y: captured");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("capturing lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("capturing boundary scan builds commit preflight metadata");

    let preflight = preflights.worker().expect("worker preflight records");
    assert_eq!(preflight.root_writeback_slots().len(), 1);
    assert_eq!(
        preflight.root_value_writeback_slots().len(),
        preflight.root_writeback_slots().len()
    );
    assert!(!preflight.heap_field_writeback_slots().is_empty());
    let expected_object_copy_bytes = preflight.object_copy_bytes();
    let expected_copy_to_nursery_bytes = preflight.copy_to_nursery_bytes();
    let expected_promote_to_old_bytes = preflight.promote_to_old_bytes();

    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("mixed boundary writeback slots apply");

    assert_eq!(
        application.report().root_writebacks(),
        application.root_writeback_slots().len()
    );
    assert_eq!(
        application.root_value_writeback_slots().len(),
        application.root_writeback_slots().len()
    );
    assert_eq!(
        application.report().heap_field_writebacks(),
        application.heap_field_writeback_slots().len()
    );
    for (slot, writeback) in application.root_writeback_slots().iter().zip(
        preflight
            .reference_writeback_plan()
            .root_writebacks()
            .writebacks(),
    ) {
        assert_eq!(slot.value(), writeback.replacement());
    }
    for (slot, writeback) in application.root_value_writeback_slots().iter().zip(
        preflight
            .reference_writeback_plan()
            .root_writebacks()
            .writebacks(),
    ) {
        assert!(
            slot.value().raw_eq(
                writeback
                    .replacement_value()
                    .expect("root typed writeback value rebuilds")
            )
        );
    }
    for (slot, writeback) in application.heap_field_writeback_slots().iter().zip(
        preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .writebacks(),
    ) {
        assert_eq!(slot.value(), writeback.replacement());
    }
    let commit_application = preflight
        .apply_commit_to_owned_buffers()
        .expect("mixed boundary commit buffers apply");
    assert_eq!(
        commit_application.report().reference_rewrites(),
        application.report().writebacks()
    );
    assert!(
        commit_application
            .object_byte_copies()
            .iter()
            .all(|copy| copy.destination_bytes() == copy.source_bytes())
    );
    let destination_storage = commit_application.destination_storage();
    let storage_report = destination_storage.copy_report();
    assert_eq!(
        storage_report.object_copies(),
        commit_application.report().object_copies()
    );
    assert_eq!(
        storage_report.nursery_payload_bytes() + storage_report.old_payload_bytes(),
        preflight.object_copy_bytes()
    );
    assert!(
        commit_application
            .forwarding_slots()
            .iter()
            .all(|slot| slot.forwarded_value().is_some())
    );

    let dry_run = preflights
        .apply_owned_commit_dry_run()
        .expect("mixed boundary dry-run applies");
    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.root_writebacks(), 1);
    assert!(summary.heap_field_writebacks() > 0);
    assert_eq!(summary.reference_rewrites(), summary.reference_writebacks());
    assert_eq!(summary.object_copy_bytes(), expected_object_copy_bytes);
    assert_eq!(
        summary.copy_to_nursery_bytes(),
        expected_copy_to_nursery_bytes
    );
    assert_eq!(
        summary.promote_to_old_bytes(),
        expected_promote_to_old_bytes
    );
    assert_eq!(
        summary.object_copies(),
        dry_run
            .commit_applications()
            .worker()
            .expect("mixed worker commit records")
            .object_byte_copies()
            .len()
    );

    let _live_reference_writebacks = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("mixed boundary installs live reference writebacks");
    let _live_destination_storage = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("mixed boundary installs live destination storage");
    let field_bindings = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings()
        .expect("mixed boundary heap-field destination bindings validate");
    let copied_binding = field_bindings
        .iter()
        .find(|binding| binding.validation_object() != binding.writeback_object())
        .expect("copied nursery heap-field binding records");
    assert_eq!(
        copied_binding.allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert!(copied_binding.writeback_object_request().is_some());

    let _live_writeback_bindings = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("mixed boundary installs live writeback destination bindings");
    let write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("mixed boundary live heap-field write plan validates");
    let copied_write = write_plan
        .writes()
        .iter()
        .find(|write| write.validation_object() != write.writeback_object())
        .expect("copied nursery heap-field write records");
    assert_eq!(
        copied_write.allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert!(copied_write.writeback_object_request().is_some());
}

#[test]
fn boundary_owned_commit_buffers_publish_retained_remembered_edges() {
    let (mut outcome, thunk_value) = boundary_remembered_edge_outcome();
    assert_eq!(outcome.value().tag(), ValueTag::Lambda);
    let _retained_edge = retain_only_thunk_resolve_edge(&mut outcome, thunk_value);

    let nursery_base = static_gc_address(0x1000_0000);
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("remembered boundary scan builds commit preflight metadata");
    let worker_preflight = preflights.worker().expect("worker preflight records");
    assert_eq!(worker_preflight.card_table().len(), 1);
    let application = preflights
        .worker()
        .expect("worker preflight records")
        .apply_commit_to_owned_buffers()
        .expect("remembered boundary commit buffers apply");

    assert_eq!(application.report().remembered_set_source_edges(), 1);
    assert_eq!(application.report().remembered_set_published_edges(), 1);
    assert_eq!(application.report().card_table_dirty_cards_cleared(), 1);
    assert_eq!(application.remembered_set().len(), 1);
    assert!(application.card_table().is_empty());
    assert_eq!(
        application.remembered_set().edges()[0].source(),
        gc_address(thunk_value)
    );
    assert_eq!(
        application.remembered_set().edges()[0].target(),
        nursery_base
    );

    let dry_run = preflights
        .apply_owned_commit_dry_run()
        .expect("remembered boundary dry-run applies");
    let summary = dry_run.summary();
    let worker_commit = dry_run
        .commit_applications()
        .worker()
        .expect("worker remembered dry-run commit records");
    let permanent_commit = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent empty dry-run commit records");
    let worker_preflight = dry_run
        .preflights()
        .worker()
        .expect("worker remembered dry-run preflight records");
    let permanent_preflight = dry_run
        .preflights()
        .permanent_shared()
        .expect("permanent empty dry-run preflight records");
    assert_eq!(worker_preflight.card_table().len(), 1);
    assert_eq!(permanent_preflight.card_table().len(), 1);

    let worker_report = worker_commit.report();
    let permanent_report = permanent_commit.report();
    assert_eq!(worker_report.card_table_dirty_cards_cleared(), 1);
    assert_eq!(permanent_report.card_table_dirty_cards_cleared(), 1);
    assert!(worker_commit.card_table().is_empty());
    assert!(permanent_commit.card_table().is_empty());

    assert_eq!(summary.tiers(), dry_run.len());
    assert_eq!(
        summary.object_copies(),
        worker_report
            .object_copies()
            .saturating_add(permanent_report.object_copies())
    );
    assert_eq!(
        summary.object_copy_bytes(),
        worker_preflight
            .object_copy_bytes()
            .saturating_add(permanent_preflight.object_copy_bytes())
    );
    assert_eq!(
        summary.copy_to_nursery_bytes(),
        worker_preflight
            .copy_to_nursery_bytes()
            .saturating_add(permanent_preflight.copy_to_nursery_bytes())
    );
    assert_eq!(
        summary.promote_to_old_bytes(),
        worker_preflight
            .promote_to_old_bytes()
            .saturating_add(permanent_preflight.promote_to_old_bytes())
    );
    assert_eq!(
        summary.reference_rewrites(),
        worker_report
            .reference_rewrites()
            .saturating_add(permanent_report.reference_rewrites())
    );
    assert_eq!(
        summary.remembered_set_source_edges(),
        worker_report
            .remembered_set_source_edges()
            .saturating_add(permanent_report.remembered_set_source_edges())
    );
    assert_eq!(
        summary.remembered_set_published_edges(),
        worker_report
            .remembered_set_published_edges()
            .saturating_add(permanent_report.remembered_set_published_edges())
    );
    assert_eq!(
        summary.card_table_dirty_cards_cleared(),
        worker_report
            .card_table_dirty_cards_cleared()
            .saturating_add(permanent_report.card_table_dirty_cards_cleared())
    );
    assert!(summary.remembered_set_source_edges() > 0);
    assert!(summary.remembered_set_published_edges() > 0);

    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    let extra_card_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(extra_card_source)
        .expect("extra live dirty card marks");
    assert_eq!(outcome.thunk_resolve_card_table().len(), 2);
    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("remembered boundary dry-run clears outcome card table");
    assert_eq!(
        live_card_table_dry_run
            .dry_run()
            .summary()
            .card_table_dirty_cards_cleared(),
        live_card_table_dry_run
            .card_table_dirty_cards_cleared()
            .saturating_mul(live_card_table_dry_run.dry_run().len())
    );
    assert_eq!(live_card_table_dry_run.card_table_dirty_cards_cleared(), 2);
    assert!(outcome.thunk_resolve_card_table().is_empty());

    let (mut forwarding_outcome, forwarding_thunk_value) = boundary_remembered_edge_outcome();
    let _forwarding_edge =
        retain_only_thunk_resolve_edge(&mut forwarding_outcome, forwarding_thunk_value);
    let live_forwarding_dry_run = forwarding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("sibling boundary preflights install merged live forwarding");
    let live_forwarding_worker = live_forwarding_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live forwarding worker commit records");
    let live_forwarding_permanent = live_forwarding_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live forwarding permanent commit records");
    let mut expected_forwarding = Vec::new();
    for slot in live_forwarding_worker
        .forwarding_slots()
        .iter()
        .chain(live_forwarding_permanent.forwarding_slots())
    {
        let Some(forwarded) = slot.forwarded_value() else {
            continue;
        };
        if let Some((_, existing)) = expected_forwarding
            .iter()
            .find(|(source, _)| *source == slot.source())
        {
            assert_eq!(*existing, forwarded);
            continue;
        }
        expected_forwarding.push((slot.source(), forwarded));
    }
    assert!(!live_forwarding_worker.forwarding_slots().is_empty());
    assert!(!live_forwarding_permanent.forwarding_slots().is_empty());
    assert!(!expected_forwarding.is_empty());
    assert_eq!(
        live_forwarding_dry_run.forwarding_pointers_installed(),
        expected_forwarding.len()
    );
    for (source, forwarded) in expected_forwarding {
        assert_eq!(
            forwarding_outcome
                .heap()
                .minor_gc_forwarding_value_at(source)
                .expect("merged forwarding source remains known"),
            Some(forwarded)
        );
    }

    let (mut destination_outcome, destination_thunk_value) = boundary_remembered_edge_outcome();
    let _destination_edge =
        retain_only_thunk_resolve_edge(&mut destination_outcome, destination_thunk_value);
    let live_destination_dry_run = destination_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("sibling boundary preflights install merged live destination bytes");
    let live_destination_worker = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live destination worker commit records");
    let live_destination_permanent = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live destination permanent commit records");
    let mut expected_destination_objects: Vec<(
        AllocationCollectorPollObjectByteCopyRequest,
        Vec<u8>,
    )> = Vec::new();
    let mut overlapping_destination_sources = 0usize;
    for object_copy in live_destination_worker
        .object_byte_copies()
        .iter()
        .chain(live_destination_permanent.object_byte_copies())
    {
        if let Some((expected_request, expected_bytes)) = expected_destination_objects
            .iter()
            .find(|(request, _)| request.source() == object_copy.request().source())
        {
            overlapping_destination_sources = overlapping_destination_sources.saturating_add(1);
            assert_eq!(*expected_request, object_copy.request());
            assert_eq!(expected_bytes.as_slice(), object_copy.destination_bytes());
            continue;
        }
        expected_destination_objects.push((
            object_copy.request(),
            object_copy.destination_bytes().to_vec(),
        ));
    }
    let live_destination_storage =
        destination_outcome.gc_stress_boundary_minor_gc_destination_storage();
    assert!(!expected_destination_objects.is_empty());
    assert!(overlapping_destination_sources > 0);
    assert_eq!(
        live_destination_dry_run.object_copies_installed(),
        expected_destination_objects.len()
    );
    assert_eq!(
        live_destination_storage.len(),
        expected_destination_objects.len()
    );
    for installed in live_destination_storage.object_bytes() {
        let (_, expected_bytes) = expected_destination_objects
            .iter()
            .find(|(request, _)| *request == installed.request())
            .expect("installed destination object has expected dry-run source");
        assert_eq!(installed.destination_bytes(), expected_bytes.as_slice());
    }

    let (mut merge_outcome, merge_thunk_value) = boundary_remembered_edge_outcome();
    let _merge_edge = retain_only_thunk_resolve_edge(&mut merge_outcome, merge_thunk_value);
    let extra_card_source = next_dirty_card_source(merge_outcome.thunk_resolve_card_table());
    merge_outcome
        .thunk_resolve_card_table
        .mark_source(extra_card_source)
        .expect("extra merge live dirty card marks");
    assert_eq!(merge_outcome.thunk_resolve_card_table().len(), 2);
    let live_remembered_set_dry_run = merge_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("sibling boundary preflights merge one live remembered set");
    assert!(live_remembered_set_dry_run.remembered_set_published());
    assert_eq!(
        live_remembered_set_dry_run.card_table_dirty_cards_cleared(),
        2
    );
    assert!(merge_outcome.thunk_resolve_card_table().is_empty());
    let live_worker_commit = live_remembered_set_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live worker commit records");
    let live_permanent_commit = live_remembered_set_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live permanent commit records");
    let mut overlapping_relocations = 0usize;
    let mut merged_relocations = Vec::new();
    for worker_slot in live_worker_commit.forwarding_slots() {
        if let Some(forwarded) = worker_slot.forwarded_value() {
            merged_relocations.push((worker_slot.source(), forwarded));
        }
        for permanent_slot in live_permanent_commit.forwarding_slots() {
            if worker_slot.source() == permanent_slot.source() {
                overlapping_relocations = overlapping_relocations.saturating_add(1);
                assert_eq!(
                    worker_slot.forwarded_value(),
                    permanent_slot.forwarded_value()
                );
            }
        }
    }
    for permanent_slot in live_permanent_commit.forwarding_slots() {
        let Some(forwarded) = permanent_slot.forwarded_value() else {
            continue;
        };
        if merged_relocations
            .iter()
            .any(|(source, _)| *source == permanent_slot.source())
        {
            continue;
        }
        if let Some(forwarded_address) = resolved_heap_destination_address(forwarded) {
            assert!(!merged_relocations.iter().any(|(_, destination)| {
                resolved_heap_destination_address(*destination) == Some(forwarded_address)
            }));
        }
        merged_relocations.push((permanent_slot.source(), forwarded));
    }
    for (_, destination) in &merged_relocations {
        let ResolvedValueGeneration::Heap { address, .. } = destination else {
            continue;
        };
        assert!(
            !merged_relocations
                .iter()
                .any(|(source, _)| source == address)
        );
    }
    assert!(overlapping_relocations > 0);
    let mut expected_merged_remembered_set =
        RememberedSet::with_epoch(live_worker_commit.remembered_set().epoch());
    for edge in live_worker_commit.remembered_set().edges() {
        expected_merged_remembered_set
            .record(*edge)
            .expect("worker edge records in expected merge");
    }
    for edge in live_permanent_commit.remembered_set().edges() {
        expected_merged_remembered_set
            .record(*edge)
            .expect("permanent edge records in expected merge");
    }
    assert_eq!(
        merge_outcome.thunk_resolve_remembered_set(),
        &expected_merged_remembered_set
    );
}

#[test]
fn boundary_owned_commit_buffers_publish_dirty_permanent_field_rescan_edges() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda evaluates");
    let permanent_parent = evaluator
        .heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(permanent_parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(permanent_parent)
        .expect("permanent parent builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(gc_address(permanent_parent))
        .expect("permanent parent card marks");
    let mut outcome = EvalOutcome {
        value: permanent_parent,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: RememberedSet::new(),
        thunk_resolve_card_table: card_table,
        memory_budget_action: None,
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans,
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
    };

    let nursery_base = static_gc_address(0x1000_0000);
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary scan builds commit preflight metadata");
    let worker_preflight = preflights.worker().expect("worker preflight records");

    assert_eq!(outcome.thunk_resolve_remembered_set().len(), 0);
    assert_eq!(worker_preflight.card_table().len(), 1);
    assert_eq!(
        worker_preflight
            .relocation_plan()
            .minor_gc_plan()
            .plan()
            .survivors()[0]
            .address(),
        gc_address(child)
    );
    assert_eq!(
        worker_preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .len(),
        1
    );
    assert!(worker_preflight.root_writeback_slots().is_empty());
    assert!(worker_preflight.root_value_writeback_slots().is_empty());
    assert_eq!(worker_preflight.heap_field_writeback_slots().len(), 1);
    assert_eq!(
        worker_preflight.heap_field_writeback_slots()[0].validation_object(),
        gc_address(permanent_parent)
    );

    let application = worker_preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("dirty permanent-field boundary writeback slots apply");
    assert_eq!(application.report().root_writebacks(), 0);
    assert_eq!(application.report().heap_field_writebacks(), 1);
    assert_eq!(
        application.heap_field_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    let commit_application = worker_preflight
        .apply_commit_to_owned_buffers()
        .expect("dirty permanent-field boundary commit buffers apply");
    assert_eq!(commit_application.report().remembered_set_source_edges(), 0);
    assert_eq!(
        commit_application.report().remembered_set_published_edges(),
        1
    );
    assert_eq!(
        commit_application.report().card_table_dirty_cards_cleared(),
        1
    );
    assert_eq!(commit_application.remembered_set().len(), 1);
    assert_eq!(
        commit_application.remembered_set().edges()[0].source(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        commit_application.remembered_set().edges()[0].target(),
        nursery_base
    );
    assert!(commit_application.card_table().is_empty());

    let dry_run = preflights
        .apply_owned_commit_dry_run()
        .expect("dirty permanent-field boundary dry-run applies");
    let summary = dry_run.summary();
    let dry_worker_commit = dry_run
        .commit_applications()
        .worker()
        .expect("worker dirty permanent-field dry-run commit records");
    let dry_permanent_commit = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent dirty permanent-field dry-run commit records");
    let dry_worker_writebacks = dry_run
        .reference_writebacks()
        .worker()
        .expect("worker dirty permanent-field writebacks record");
    let dry_permanent_writebacks = dry_run
        .reference_writebacks()
        .permanent_shared()
        .expect("permanent dirty permanent-field writebacks record");
    let dry_worker_report = dry_worker_commit.report();
    let dry_permanent_report = dry_permanent_commit.report();

    assert_eq!(summary.tiers(), dry_run.len());
    let canonical_heap_field_writebacks = 1usize;
    let canonical_writeback_destination_bindings = summary
        .root_writebacks()
        .saturating_add(canonical_heap_field_writebacks);
    assert_eq!(
        summary.root_writebacks(),
        dry_worker_writebacks
            .report()
            .root_writebacks()
            .saturating_add(dry_permanent_writebacks.report().root_writebacks())
    );
    assert_eq!(
        summary.heap_field_writebacks(),
        dry_worker_writebacks
            .report()
            .heap_field_writebacks()
            .saturating_add(dry_permanent_writebacks.report().heap_field_writebacks())
    );
    assert_eq!(
        summary.reference_rewrites(),
        dry_worker_report
            .reference_rewrites()
            .saturating_add(dry_permanent_report.reference_rewrites())
    );
    assert_eq!(
        summary.remembered_set_source_edges(),
        dry_worker_report
            .remembered_set_source_edges()
            .saturating_add(dry_permanent_report.remembered_set_source_edges())
    );
    assert_eq!(
        summary.remembered_set_published_edges(),
        dry_worker_report
            .remembered_set_published_edges()
            .saturating_add(dry_permanent_report.remembered_set_published_edges())
    );
    assert_eq!(
        summary.card_table_dirty_cards_cleared(),
        dry_worker_report
            .card_table_dirty_cards_cleared()
            .saturating_add(dry_permanent_report.card_table_dirty_cards_cleared())
    );
    assert_eq!(summary.heap_field_writebacks(), 2);
    assert_eq!(dry_worker_report.remembered_set_source_edges(), 0);
    assert_eq!(dry_worker_report.remembered_set_published_edges(), 1);

    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let live_writeback_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary installs live writeback metadata");
    assert_eq!(
        live_writeback_dry_run.reference_writebacks_installed(),
        summary.reference_writebacks()
    );
    assert_eq!(
        live_writeback_dry_run
            .reference_writeback_install_report()
            .heap_field_writebacks(),
        summary.heap_field_writebacks()
    );
    let live_writebacks = outcome.gc_stress_boundary_minor_gc_reference_writebacks();
    let live_worker_writebacks = live_writebacks
        .worker()
        .expect("dirty permanent-field worker writebacks install");
    assert_eq!(live_writebacks.len(), dry_run.reference_writebacks().len());
    assert_eq!(
        live_writebacks.install_report().writebacks(),
        summary.reference_writebacks()
    );
    assert_eq!(
        live_worker_writebacks.heap_field_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    let binding_err = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings()
        .expect_err("destination binding requires installed destination bytes");
    assert!(matches!(
        binding_err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
            replacement,
            ..
        } if replacement == nursery_base
    ));
    let live_destination_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary installs live destination storage");
    let live_destination_storage = outcome.gc_stress_boundary_minor_gc_destination_storage();
    let live_object_copy = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("worker destination storage records object copy")
        .object_byte_copies()[0]
        .clone();
    assert_eq!(live_destination_storage.len(), 1);
    assert_eq!(
        live_destination_storage.object_bytes()[0].request(),
        live_object_copy.request()
    );
    let field_bindings = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings()
        .expect("heap-field writeback destination bindings validate");
    assert_eq!(field_bindings.len(), canonical_heap_field_writebacks);
    let dirty_field_binding = field_bindings
        .iter()
        .find(|binding| {
            binding.validation_object() == gc_address(permanent_parent)
                && binding.writeback_object() == gc_address(permanent_parent)
        })
        .expect("dirty permanent-field binding records");
    assert_eq!(
        dirty_field_binding.allocation_domain(),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        dirty_field_binding.validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        dirty_field_binding.writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(dirty_field_binding.field_index(), 0);
    assert_eq!(
        dirty_field_binding.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(dirty_field_binding.replacement_destination(), nursery_base);
    assert_eq!(
        dirty_field_binding.replacement_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        dirty_field_binding.replacement_request(),
        live_object_copy.request()
    );
    assert_eq!(
        dirty_field_binding.replacement_destination_bytes(),
        live_object_copy.destination_bytes()
    );
    assert_eq!(dirty_field_binding.writeback_object_request(), None);
    assert_eq!(
        dirty_field_binding.writeback_object_destination_bytes(),
        None
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    let live_writeback_binding_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary installs live writeback destination bindings");
    assert_eq!(
        live_writeback_binding_dry_run.writeback_destination_bindings_installed(),
        canonical_writeback_destination_bindings
    );
    assert_eq!(
        live_writeback_binding_dry_run.heap_field_writeback_destination_bindings_installed(),
        canonical_heap_field_writebacks
    );
    let live_writeback_destination_bindings =
        outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings();
    assert_eq!(
        live_writeback_destination_bindings.len(),
        canonical_writeback_destination_bindings
    );
    assert_eq!(
        live_writeback_destination_bindings
            .install_report()
            .heap_field_writeback_bindings(),
        canonical_heap_field_writebacks
    );
    let installed_dirty_field_binding = live_writeback_destination_bindings
        .heap_field_writeback_bindings()
        .iter()
        .find(|binding| {
            binding.validation_object() == gc_address(permanent_parent)
                && binding.writeback_object() == gc_address(permanent_parent)
        })
        .expect("installed dirty permanent-field binding records");
    assert_eq!(installed_dirty_field_binding, dirty_field_binding);
    let heap_field_writeback_write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback write plan validates installed live metadata");
    assert_eq!(
        heap_field_writeback_write_plan.len(),
        canonical_heap_field_writebacks
    );
    assert_eq!(
        heap_field_writeback_write_plan.report().fields(),
        canonical_heap_field_writebacks
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .copied_replacements_to_nursery(),
        canonical_heap_field_writebacks
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .promoted_replacements_to_old(),
        0
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .replacement_payload_bytes(),
        live_object_copy
            .destination_bytes()
            .len()
            .saturating_mul(canonical_heap_field_writebacks)
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .writeback_object_payload_bytes(),
        0
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].allocation_domain(),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(heap_field_writeback_write_plan.writes()[0].field_index(), 0);
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_destination(),
        nursery_base
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_metadata(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_request(),
        live_object_copy.request()
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_destination_bytes(),
        live_object_copy.destination_bytes()
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].writeback_object_request(),
        None
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].writeback_object_destination_bytes(),
        None
    );

    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary dry-run clears outcome card table");
    assert_eq!(
        live_card_table_dry_run
            .dry_run()
            .summary()
            .card_table_dirty_cards_cleared(),
        summary.card_table_dirty_cards_cleared()
    );
    assert_eq!(live_card_table_dry_run.card_table_dirty_cards_cleared(), 1);
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn boundary_minor_gc_plans_reject_remembered_edge_without_dirty_card() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark source thunk permanent");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(forced)
        .expect("forced value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let remembered_set = evaluator.thunk_resolve_remembered_set;
    let edge = RememberedEdge::new(gc_address(thunk_value), gc_address(forced));
    assert!(
        remembered_set.edges().contains(&edge),
        "thunk-resolution write barrier records forced value edge"
    );
    let remembered_set = remembered_set_with_only_edge(&remembered_set, edge);
    let outcome = EvalOutcome {
        value: forced,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: remembered_set,
        thunk_resolve_card_table: GcCardTable::default(),
        memory_budget_action: None,
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans,
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
    };

    let error = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect_err("boundary planning requires dirty remembered source card");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollDirtyCard {
            source_address: edge.source(),
            target_address: edge.target(),
            card_index: outcome
                .thunk_resolve_card_table()
                .snapshot()
                .card_index_for_source(edge.source()),
        }
    );
}

#[test]
fn boundary_live_card_table_clear_waits_for_successful_commit_dry_run() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark source thunk permanent");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(forced)
        .expect("forced value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let remembered_set = evaluator.thunk_resolve_remembered_set;
    let edge = RememberedEdge::new(gc_address(thunk_value), gc_address(forced));
    assert!(
        remembered_set.edges().contains(&edge),
        "thunk-resolution write barrier records forced value edge"
    );
    let remembered_set = remembered_set_with_only_edge(&remembered_set, edge);
    let wrong_card_source = static_gc_address(0x4000_0000);
    let mut wrong_card_table = GcCardTable::default();
    wrong_card_table
        .mark_source(wrong_card_source)
        .expect("wrong card marks");
    let mut outcome = EvalOutcome {
        value: forced,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: remembered_set,
        thunk_resolve_card_table: wrong_card_table,
        memory_budget_action: None,
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans,
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
    };

    let error = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect_err("missing dirty source card rejects before live clear");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollDirtyCard {
            source_address: edge.source(),
            target_address: edge.target(),
            card_index: outcome
                .thunk_resolve_card_table()
                .snapshot()
                .card_index_for_source(edge.source()),
        }
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards()[0].source(),
        wrong_card_source
    );
}

#[test]
fn owned_eval_reports_gc_stress_boundary_permanent_commit_preflight() {
    let ir = lower("\"stress\"");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan builds commit preflight metadata");

    assert_eq!(preflights.len(), 1);
    assert!(preflights.worker().is_none());
    let preflight = preflights
        .permanent_shared()
        .expect("permanent preflight records");
    assert!(
        preflight
            .relocation_plan()
            .minor_gc_plan()
            .plan()
            .is_empty()
    );
    assert!(preflight.object_byte_copy_plan().is_empty());
    assert!(preflight.forwarding_slots().is_empty());
    assert_eq!(
        preflight.reference_buffer(),
        preflight
            .relocation_plan()
            .minor_gc_plan()
            .reference_values()
            .collect::<Vec<_>>()
    );
    assert!(preflight.reference_buffer().iter().all(|value| matches!(
        value,
        ResolvedValueGeneration::Heap {
            generation: HeapGeneration::Permanent,
            ..
        }
    )));
    assert!(preflight.reference_writeback_plan().is_empty());
    assert!(preflight.root_writeback_slots().is_empty());
    assert!(preflight.root_value_writeback_slots().is_empty());
    assert!(preflight.heap_field_writeback_slots().is_empty());
    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("empty boundary writeback slots apply");
    assert_eq!(application.report().writebacks(), 0);
    assert!(application.root_writeback_slots().is_empty());
    assert!(application.root_value_writeback_slots().is_empty());
    assert!(application.heap_field_writeback_slots().is_empty());
    let commit_application = preflight
        .apply_commit_to_owned_buffers()
        .expect("empty boundary commit buffers apply");
    assert_eq!(commit_application.report().object_copies(), 0);
    assert_eq!(commit_application.report().forwarding_pointers(), 0);
    assert_eq!(commit_application.report().reference_rewrites(), 0);
    assert!(commit_application.object_byte_copies().is_empty());
    assert_eq!(
        commit_application
            .destination_storage()
            .copy_report()
            .object_copies(),
        0
    );
    assert!(commit_application.forwarding_slots().is_empty());
    assert_eq!(
        commit_application.references(),
        preflight.reference_buffer()
    );
    assert!(commit_application.remembered_set().is_empty());

    let applications = preflights
        .apply_reference_writebacks_to_owned_slots()
        .expect("permanent boundary preflight applies owned writeback slots");
    assert_eq!(applications.len(), 1);
    assert!(applications.worker().is_none());
    assert_eq!(applications.permanent_shared(), Some(&application));
    let commit_applications = preflights
        .apply_commits_to_owned_buffers()
        .expect("permanent boundary preflight applies owned commit buffers");
    assert_eq!(commit_applications.len(), 1);
    assert!(commit_applications.worker().is_none());
    assert_eq!(
        commit_applications.permanent_shared(),
        Some(&commit_application)
    );

    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let live_writeback_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("no-writeback boundary dry-run is a live side-table no-op");
    assert_eq!(live_writeback_dry_run.dry_run().len(), 1);
    assert_eq!(
        live_writeback_dry_run
            .dry_run()
            .reference_writebacks()
            .permanent_shared()
            .expect("permanent no-writeback application records")
            .report()
            .writebacks(),
        0
    );
    assert_eq!(live_writeback_dry_run.reference_writebacks_installed(), 0);
    assert_eq!(
        live_writeback_dry_run
            .reference_writeback_install_report()
            .tiers(),
        0
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let repeat_noop = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("repeated no-writeback live side-table run stays a no-op");
    assert_eq!(repeat_noop.reference_writebacks_installed(), 0);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_commit_preflights() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty commit preflight metadata");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(preflights.is_empty());
    let applications = preflights
        .apply_reference_writebacks_to_owned_slots()
        .expect("empty boundary preflights produce empty writeback application");
    assert!(applications.is_empty());
    let commit_applications = preflights
        .apply_commits_to_owned_buffers()
        .expect("empty boundary preflights produce empty commit application");
    assert!(commit_applications.is_empty());

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty dry-run application");
    assert!(dry_run.is_empty());
    assert_eq!(dry_run.len(), 0);
    assert!(dry_run.preflights().is_empty());
    assert!(dry_run.reference_writebacks().is_empty());
    assert!(dry_run.commit_applications().is_empty());

    let unrelated_dirty_source = static_gc_address(0x1000_0000);
    outcome
        .thunk_resolve_card_table
        .mark_source(unrelated_dirty_source)
        .expect("unrelated dirty card marks");
    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run succeeds without clearing live cards");
    assert!(live_card_table_dry_run.dry_run().is_empty());
    assert_eq!(live_card_table_dry_run.card_table_dirty_cards_cleared(), 0);
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards()[0].source(),
        unrelated_dirty_source
    );
    let empty_live_forwarding_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run leaves live forwarding alone");
    assert!(empty_live_forwarding_dry_run.dry_run().is_empty());
    assert_eq!(
        empty_live_forwarding_dry_run.forwarding_pointers_installed(),
        0
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_header_write_plan()
            .expect("empty boundary has no forwarding header writes")
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_root_writeback_write_plan()
            .expect("empty boundary has no root writeback writes")
            .is_empty()
    );
    let empty_live_destination_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run leaves live destination storage alone");
    assert!(empty_live_destination_dry_run.dry_run().is_empty());
    assert_eq!(empty_live_destination_dry_run.object_copies_installed(), 0);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    let remembered_set_before_empty = outcome.thunk_resolve_remembered_set().clone();
    let empty_live_state_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run leaves live GC metadata alone");
    assert!(empty_live_state_dry_run.dry_run().is_empty());
    assert!(!empty_live_state_dry_run.remembered_set_published());
    assert_eq!(empty_live_state_dry_run.card_table_dirty_cards_cleared(), 0);
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        &remembered_set_before_empty
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_relocation_destinations() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty destinations");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(destinations.is_empty());
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_relocation_plans() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty paired plans");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(plans.is_empty());
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_minor_gc_plans() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("empty boundary scans produce empty plans");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(plans.is_empty());
}

#[test]
fn gc_stress_poll_scan_rejects_stale_allocator_poll() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let first_root = evaluator.eval_root().expect("first lambda evaluates");
    let first_poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("first lambda allocation requested a collector poll");
    let _second_root = evaluator.eval_root().expect("second lambda evaluates");

    let error = evaluator
        .safepoint_collector_poll_scan(first_poll, [first_root])
        .expect_err("stale collector poll is rejected");

    match error {
        TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        } => {
            assert_eq!(poll, first_poll);
            assert_ne!(current, first_poll);
            assert_eq!(
                current.entrypoint(),
                RuntimeAllocationEntryPoint::AosAllocLambda
            );
            assert_eq!(
                current.reason(),
                AllocationGcPollReason::GcStressEverySafepoint
            );
        }
        other => panic!("unexpected stale poll error: {other:?}"),
    }
}
