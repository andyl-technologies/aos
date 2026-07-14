//! Split-out tests (part_7). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
