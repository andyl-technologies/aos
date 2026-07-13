//! Split-out tests (part_11). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

