//! Split-out tests (part_8). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
