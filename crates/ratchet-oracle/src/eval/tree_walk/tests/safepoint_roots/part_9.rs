//! Split-out tests (part_9). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

