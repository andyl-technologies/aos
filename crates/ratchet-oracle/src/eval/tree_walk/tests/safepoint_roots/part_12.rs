//! Split-out tests (part_12). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

