//! Split-out tests (part_10). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

