//! Split-out tests (part_13). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

