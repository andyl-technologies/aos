//! Split-out tests (part_6). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

