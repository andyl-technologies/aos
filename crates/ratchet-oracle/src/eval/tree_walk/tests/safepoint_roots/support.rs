//! Shared helpers for the safepoint-roots tests (extracted for the §2 cap).

use super::*;

pub(crate) fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

pub(crate) fn static_gc_address(address_bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(address_bits).expect("static address is a valid GC address")
}

pub(crate) fn relocated_value(tag: ValueTag, address: GcHeapAddress) -> Value {
    Value::heap(
        tag,
        NonNull::new(address.address_bits() as *mut HeapObject)
            .expect("relocated heap address is non-null"),
    )
    .expect("relocated heap value rebuilds")
}

pub(crate) fn test_lambda_record() -> EvalLambda {
    EvalLambda::new(
        IrId::new(0),
        IrId::new(0),
        FrameId::new(0),
        EvalEnv::default(),
    )
}

pub(crate) fn resolved_heap_destination_address(
    value: ResolvedValueGeneration,
) -> Option<GcHeapAddress> {
    let ResolvedValueGeneration::Heap { address, .. } = value else {
        return None;
    };

    Some(address)
}

pub(crate) fn has_forwarding_destination(heap: &EvalHeap, destination: Value) -> bool {
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

pub(crate) fn remembered_set_with_only_edge(
    source: &RememberedSet,
    edge: RememberedEdge,
) -> RememberedSet {
    let mut remembered_set = RememberedSet::with_epoch(source.epoch());
    remembered_set
        .record(edge)
        .expect("single remembered edge records");
    remembered_set
}

pub(crate) fn retain_only_thunk_resolve_edge(
    outcome: &mut EvalOutcome,
    thunk_value: Value,
) -> RememberedEdge {
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

pub(crate) fn next_dirty_card_source(card_table: &GcCardTable) -> GcHeapAddress {
    let next_index = card_table
        .dirty_cards()
        .iter()
        .map(|card| card.index())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    static_gc_address(next_index.saturating_mul(card_table.card_size_bytes()))
}

pub(crate) fn boundary_remembered_edge_outcome() -> (EvalOutcome, Value) {
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

pub(crate) fn boundary_lambda_outcome_with_existing_destination() -> (EvalOutcome, Value, Value) {
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

pub(crate) fn boundary_permanent_list_field_outcome_with_existing_destination()
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

pub(crate) fn boundary_root_and_permanent_lambda_field_outcome_with_existing_destination()
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

pub(crate) fn boundary_distinct_root_and_permanent_lambda_field_outcome()
-> (EvalOutcome, Value, Value, Value) {
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

pub(crate) fn scan_has_value_stack_root(scan: &AllocationCollectorPollScan, value: Value) -> bool {
    scan.scan().roots().iter().any(|scan_root| {
        scan_root.source() == &EvalRootSource::ValueStack { slot: 0 }
            && scan_root.value().raw_eq(value)
    })
}

pub(crate) fn scan_has_object(scan: &AllocationCollectorPollScan, value: Value) -> bool {
    scan.scan()
        .objects()
        .iter()
        .any(|object| object.value().raw_eq(value))
}

pub(crate) fn tree_walk_with_supported_mutable_roots() -> (TreeWalk, Value, Vec<Value>) {
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

pub(crate) fn alloc_test_lambda(evaluator: &mut TreeWalk, id: u32) -> Value {
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

pub(crate) fn tree_walk_with_indexed_mutable_roots() -> (TreeWalk, Vec<Value>) {
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

pub(crate) fn root_writeback_plan_for_supported_mutable_roots(
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

pub(crate) fn root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
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

pub(crate) fn tree_walk_with_mixed_root_and_heap_field_writebacks()
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

pub(crate) fn tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination() -> (
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

pub(crate) fn assert_supported_mutable_roots_eq(
    evaluator: &TreeWalk,
    value_stack: &[Value],
    expected: Value,
) {
    assert!(value_stack[0].raw_eq(expected));
    assert_supported_tree_walk_roots_eq(evaluator, expected);
}

pub(crate) fn assert_supported_tree_walk_roots_eq(evaluator: &TreeWalk, expected: Value) {
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

pub(crate) fn replacement_for_source(
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

pub(crate) fn assert_raw_eq(actual: Value, expected: Value) {
    assert!(
        actual.raw_eq(expected),
        "expected tag {:?}/payload {:#x}, got tag {:?}/payload {:#x}",
        expected.tag(),
        expected.payload_bits(),
        actual.tag(),
        actual.payload_bits()
    );
}
