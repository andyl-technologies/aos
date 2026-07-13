//! GC-planning unit tests, part 4 of 5 (RFC-0007 §2 split, #9).
//!
//! Move-only line-boundary split of `gc/tests.rs`; no test changed.

use super::super::*;
use super::address;

#[test]
fn minor_gc_commit_plan_composes_validated_subplans() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let remembered_source = address(0x3000);
    let promoted_source = address(0x4000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(copy, copy_destination),
            MinorGcRelocationDestination::new(promote, promote_destination),
        ],
    )
    .expect("relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 24, 8),
            NurseryObjectLayout::new(promote, 40, 16),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");
    let reference_rewrites = MinorGcReferenceRewritePlan::from_references(
        &relocation_plan,
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
    )
    .expect("reference rewrite plan builds");
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    remembered_set
        .record(RememberedEdge::new(remembered_source, copy))
        .expect("remembered copy edge records");
    remembered_set
        .record(RememberedEdge::new(promoted_source, promote))
        .expect("remembered promote edge records");
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");

    let commit_plan = MinorGcCommitPlan::from_parts(
        object_copies.clone(),
        forwarding_pointers.clone(),
        reference_rewrites.clone(),
        remembered_set_refresh.clone(),
    )
    .expect("commit plan builds");

    assert_eq!(commit_plan.object_copies(), &object_copies);
    assert_eq!(commit_plan.forwarding_pointers(), &forwarding_pointers);
    assert_eq!(commit_plan.reference_rewrites(), &reference_rewrites);
    assert_eq!(
        commit_plan.remembered_set_refresh(),
        &remembered_set_refresh
    );
    assert_eq!(
        commit_plan.next_remembered_set().epoch(),
        RememberedSetEpoch::new(8)
    );
    assert_eq!(
        commit_plan.next_remembered_set().edges(),
        &[RememberedEdge::new(remembered_source, copy_destination)]
    );

    commit_plan
        .publish_next_remembered_set(&mut remembered_set)
        .expect("remembered set publishes");
    assert_eq!(remembered_set.epoch(), RememberedSetEpoch::new(8));
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(remembered_source, copy_destination)]
    );
}

#[test]
fn minor_gc_commit_plan_composes_dirty_old_field_rescan() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let dead = address(0x5000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let remembered_source = address(0x3000);
    let promoted_source = address(0x4000);
    let extra_source = address(0x6000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(copy, copy_destination),
            MinorGcRelocationDestination::new(promote, promote_destination),
        ],
    )
    .expect("relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 24, 8),
            NurseryObjectLayout::new(promote, 40, 16),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    remembered_set
        .record(RememberedEdge::new(remembered_source, copy))
        .expect("remembered copy edge records");
    remembered_set
        .record(RememberedEdge::new(promoted_source, promote))
        .expect("remembered promote edge records");
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");
    card_table
        .mark_source(remembered_source)
        .expect("remembered source card marks");
    card_table
        .mark_source(extra_source)
        .expect("extra source card marks");
    let remembered_source_fields = [ResolvedValueGeneration::young(copy)];
    let extra_source_fields = [
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::young(promote),
        ResolvedValueGeneration::young(dead),
    ];
    let old_fields = [
        MinorGcOldObjectFields::new(
            remembered_source,
            HeapGeneration::Old,
            &remembered_source_fields,
        ),
        MinorGcOldObjectFields::new(extra_source, HeapGeneration::Old, &extra_source_fields),
    ];
    let old_field_rescan = MinorGcOldFieldRescanPlan::from_dirty_cards(
        card_table.snapshot(),
        &old_fields,
        &relocation_plan,
    )
    .expect("old-field rescan builds");

    let commit_plan = MinorGcCommitPlan::from_parts_with_old_field_rescan(
        object_copies,
        forwarding_pointers,
        MinorGcReferenceRewritePlan::default(),
        remembered_set_refresh,
        &old_field_rescan,
    )
    .expect("commit plan with old-field rescan builds");

    assert_eq!(
        commit_plan.next_remembered_set().edges(),
        &[
            RememberedEdge::new(remembered_source, copy_destination),
            RememberedEdge::new(extra_source, copy_destination),
        ]
    );
    commit_plan
        .publish_next_remembered_set(&mut remembered_set)
        .expect("remembered set publishes");
    assert_eq!(remembered_set.epoch(), RememberedSetEpoch::new(8));
    assert_eq!(
        remembered_set.edges(),
        &[
            RememberedEdge::new(remembered_source, copy_destination),
            RememberedEdge::new(extra_source, copy_destination),
        ]
    );
}

#[test]
fn minor_gc_commit_plan_applies_to_caller_owned_buffers() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let remembered_source = address(0x3000);
    let promoted_source = address(0x4000);
    let ignored_old = address(0x5000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(copy, copy_destination),
            MinorGcRelocationDestination::new(promote, promote_destination),
        ],
    )
    .expect("relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 4, 4),
            NurseryObjectLayout::new(promote, 4, 4),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");
    let mut references = [
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::old(ignored_old),
        ResolvedValueGeneration::young(promote),
    ];
    let reference_rewrites =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, references)
            .expect("reference rewrite plan builds");
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    remembered_set
        .record(RememberedEdge::new(remembered_source, copy))
        .expect("remembered copy edge records");
    remembered_set
        .record(RememberedEdge::new(promoted_source, promote))
        .expect("remembered promote edge records");
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");
    let commit_plan = MinorGcCommitPlan::from_parts(
        object_copies,
        forwarding_pointers,
        reference_rewrites,
        remembered_set_refresh,
    )
    .expect("commit plan builds");
    let copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8];
    let mut copy_destination_bytes = [0; 4];
    let mut promote_destination_bytes = [0; 4];
    let mut object_byte_copies = [
        MinorGcObjectByteCopyBuffer::new(
            copy,
            copy_destination,
            &copy_source,
            &mut copy_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            promote,
            promote_destination,
            &promote_source,
            &mut promote_destination_bytes,
        ),
    ];
    let mut forwarding_slots = [
        MinorGcForwardingSlot::new(copy),
        MinorGcForwardingSlot::new(promote),
    ];
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");
    card_table
        .mark_source(remembered_source)
        .expect("remembered source card marks");
    card_table
        .mark_source(promoted_source)
        .expect("promoted source card marks");

    let report = commit_plan
        .apply_to_buffers_with_report(MinorGcCommitBuffers::with_card_table(
            &mut object_byte_copies,
            &mut forwarding_slots,
            &mut references,
            &mut remembered_set,
            &mut card_table,
        ))
        .expect("commit applies");

    assert_eq!(report.object_copies(), 2);
    assert_eq!(report.copied_to_nursery(), 1);
    assert_eq!(report.promoted_to_old(), 1);
    assert_eq!(report.forwarding_pointers(), 2);
    assert_eq!(report.reference_rewrites(), 2);
    assert_eq!(
        report.remembered_set_source_epoch(),
        RememberedSetEpoch::new(7)
    );
    assert_eq!(
        report.remembered_set_next_epoch(),
        RememberedSetEpoch::new(8)
    );
    assert_eq!(report.remembered_set_source_edges(), 2);
    assert_eq!(report.remembered_set_published_edges(), 1);
    assert_eq!(report.card_table_dirty_cards_cleared(), 2);
    assert_eq!(object_byte_copies[0].destination_bytes(), copy_source);
    assert_eq!(object_byte_copies[1].destination_bytes(), promote_source);
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::young(copy_destination))
    );
    assert_eq!(
        forwarding_slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::old(promote_destination))
    );
    assert_eq!(
        references,
        [
            ResolvedValueGeneration::young(copy_destination),
            ResolvedValueGeneration::old(ignored_old),
            ResolvedValueGeneration::old(promote_destination),
        ]
    );
    assert_eq!(remembered_set.epoch(), RememberedSetEpoch::new(8));
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(remembered_source, copy_destination)]
    );
    assert!(card_table.is_empty());
}

#[test]
fn minor_gc_commit_plan_applies_to_owned_destination_storage() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let remembered_source = address(0x3000);
    let promoted_source = address(0x4000);
    let ignored_old = address(0x5000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let layouts = [
        NurseryObjectLayout::new(copy, 4, 8),
        NurseryObjectLayout::new(promote, 4, 8),
    ];
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(&plan, &layouts)
        .expect("allocation plan builds");
    let placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)
            .expect("placement plan builds");
    let mut destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(&placement_plan)
            .expect("owned destination storage allocates");
    let relocation_destination_plan = destination_storage
        .relocation_destination_plan(&plan)
        .expect("relocation destinations materialize");
    let relocation_plan = relocation_destination_plan
        .relocation_plan(&plan)
        .expect("relocation plan builds");
    let copy_destination = relocation_plan.relocations()[0].destination();
    let promote_destination = relocation_plan.relocations()[1].destination();
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, &layouts)
        .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");
    let mut references = [
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::old(ignored_old),
        ResolvedValueGeneration::young(promote),
    ];
    let reference_rewrites =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, references)
            .expect("reference rewrite plan builds");
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    remembered_set
        .record(RememberedEdge::new(remembered_source, copy))
        .expect("remembered copy edge records");
    remembered_set
        .record(RememberedEdge::new(promoted_source, promote))
        .expect("remembered promote edge records");
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");
    let commit_plan = MinorGcCommitPlan::from_parts(
        object_copies,
        forwarding_pointers,
        reference_rewrites,
        remembered_set_refresh,
    )
    .expect("commit plan builds");
    let copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8];
    let source_bytes = [
        MinorGcSourceObjectBytes::new(copy, &copy_source),
        MinorGcSourceObjectBytes::new(promote, &promote_source),
    ];
    let mut forwarding_slots = [
        MinorGcForwardingSlot::new(copy),
        MinorGcForwardingSlot::new(promote),
    ];
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");
    card_table
        .mark_source(remembered_source)
        .expect("remembered source card marks");
    card_table
        .mark_source(promoted_source)
        .expect("promoted source card marks");

    let report = commit_plan
        .apply_to_owned_destination_storage_with_report(
            MinorGcOwnedCommitBuffers::with_card_table(
                &mut destination_storage,
                &source_bytes,
                &mut forwarding_slots,
                &mut references,
                &mut remembered_set,
                &mut card_table,
            ),
        )
        .expect("owned-storage commit applies");

    assert_eq!(report.object_copies(), 2);
    assert_eq!(report.copied_to_nursery(), 1);
    assert_eq!(report.promoted_to_old(), 1);
    assert_eq!(report.forwarding_pointers(), 2);
    assert_eq!(report.reference_rewrites(), 2);
    assert_eq!(report.remembered_set_published_edges(), 1);
    assert_eq!(report.card_table_dirty_cards_cleared(), 2);
    assert_eq!(destination_storage.nursery_destination_bytes(), copy_source);
    assert_eq!(destination_storage.old_destination_bytes(), promote_source);
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::young(copy_destination))
    );
    assert_eq!(
        forwarding_slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::old(promote_destination))
    );
    assert_eq!(
        references,
        [
            ResolvedValueGeneration::young(copy_destination),
            ResolvedValueGeneration::old(ignored_old),
            ResolvedValueGeneration::old(promote_destination),
        ]
    );
    assert_eq!(remembered_set.epoch(), RememberedSetEpoch::new(8));
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(remembered_source, copy_destination)]
    );
    assert!(card_table.is_empty());
}

#[test]
fn minor_gc_owned_storage_commit_rejects_unplanned_young_reference_without_partial_writes() {
    let copy = address(0x1000);
    let late_young = address(0x2000);
    let remembered_source = address(0x3000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(copy)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(copy, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let layouts = [NurseryObjectLayout::new(copy, 4, 8)];
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(&plan, &layouts)
        .expect("allocation plan builds");
    let placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)
            .expect("placement plan builds");
    let mut destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(&placement_plan)
            .expect("owned destination storage allocates");
    let relocation_destination_plan = destination_storage
        .relocation_destination_plan(&plan)
        .expect("relocation destinations materialize");
    let relocation_plan = relocation_destination_plan
        .relocation_plan(&plan)
        .expect("relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, &layouts)
        .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");
    let mut references = [
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::Inline,
    ];
    let reference_rewrites =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, references)
            .expect("reference rewrite plan builds");
    references[1] = ResolvedValueGeneration::young(late_young);
    let unchanged_references = references;
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    let unchanged_remembered_set = remembered_set.clone();
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");
    let commit_plan = MinorGcCommitPlan::from_parts(
        object_copies,
        forwarding_pointers,
        reference_rewrites,
        remembered_set_refresh,
    )
    .expect("commit plan builds");
    let copy_source = [1, 2, 3, 4];
    let source_bytes = [MinorGcSourceObjectBytes::new(copy, &copy_source)];
    let mut forwarding_slots = [MinorGcForwardingSlot::new(copy)];
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");
    card_table
        .mark_source(remembered_source)
        .expect("remembered source card marks");
    let unchanged_card_table = card_table.clone();

    assert_eq!(
        commit_plan.apply_to_owned_destination_storage(
            MinorGcOwnedCommitBuffers::with_card_table(
                &mut destination_storage,
                &source_bytes,
                &mut forwarding_slots,
                &mut references,
                &mut remembered_set,
                &mut card_table,
            ),
        ),
        Err(
            GenerationalGcError::MinorGcReferenceRewriteUnplannedYoungSlot {
                slot: 1,
                address: late_young,
            }
        )
    );
    assert_eq!(destination_storage.nursery_destination_bytes(), [0; 4]);
    assert!(forwarding_slots[0].is_empty());
    assert_eq!(references, unchanged_references);
    assert_eq!(remembered_set, unchanged_remembered_set);
    assert_eq!(card_table, unchanged_card_table);
}

#[test]
fn minor_gc_owned_storage_commit_rejects_late_state_without_partial_writes() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let remembered_source = address(0x3000);
    let promoted_source = address(0x4000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let layouts = [
        NurseryObjectLayout::new(copy, 4, 8),
        NurseryObjectLayout::new(promote, 4, 8),
    ];
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(&plan, &layouts)
        .expect("allocation plan builds");
    let placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)
            .expect("placement plan builds");
    let mut destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(&placement_plan)
            .expect("owned destination storage allocates");
    let relocation_destination_plan = destination_storage
        .relocation_destination_plan(&plan)
        .expect("relocation destinations materialize");
    let relocation_plan = relocation_destination_plan
        .relocation_plan(&plan)
        .expect("relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, &layouts)
        .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");
    let mut references = [
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::young(promote),
    ];
    let original_references = references;
    let reference_rewrites =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, references)
            .expect("reference rewrite plan builds");
    let mut source_remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    source_remembered_set
        .record(RememberedEdge::new(remembered_source, copy))
        .expect("remembered copy edge records");
    source_remembered_set
        .record(RememberedEdge::new(promoted_source, promote))
        .expect("remembered promote edge records");
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        source_remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");
    let commit_plan = MinorGcCommitPlan::from_parts(
        object_copies,
        forwarding_pointers,
        reference_rewrites,
        remembered_set_refresh,
    )
    .expect("commit plan builds");
    let copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8];
    let source_bytes = [
        MinorGcSourceObjectBytes::new(copy, &copy_source),
        MinorGcSourceObjectBytes::new(promote, &promote_source),
    ];
    let mut forwarding_slots = [
        MinorGcForwardingSlot::new(copy),
        MinorGcForwardingSlot::new(promote),
    ];
    let mut stale_remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(8));
    stale_remembered_set
        .record(RememberedEdge::new(remembered_source, copy))
        .expect("stale remembered copy edge records");
    stale_remembered_set
        .record(RememberedEdge::new(promoted_source, promote))
        .expect("stale remembered promote edge records");
    let unchanged_stale_remembered_set = stale_remembered_set.clone();
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");
    card_table
        .mark_source(remembered_source)
        .expect("remembered source card marks");
    let unchanged_card_table = card_table.clone();

    assert_eq!(
        commit_plan.apply_to_owned_destination_storage(
            MinorGcOwnedCommitBuffers::with_card_table(
                &mut destination_storage,
                &source_bytes,
                &mut forwarding_slots,
                &mut references,
                &mut stale_remembered_set,
                &mut card_table,
            ),
        ),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch {
                expected: RememberedSetEpoch::new(7),
                actual: RememberedSetEpoch::new(8),
            }
        )
    );
    assert_eq!(destination_storage.nursery_destination_bytes(), [0; 4]);
    assert_eq!(destination_storage.old_destination_bytes(), [0; 4]);
    assert!(forwarding_slots[0].is_empty());
    assert!(forwarding_slots[1].is_empty());
    assert_eq!(references, original_references);
    assert_eq!(stale_remembered_set, unchanged_stale_remembered_set);
    assert_eq!(card_table, unchanged_card_table);
}

#[test]
fn minor_gc_commit_plan_rejects_inconsistent_old_field_rescan() {
    let target = address(0x1000);
    let source = address(0x3000);
    let copied_destination = address(0x9000);
    let promoted_destination = address(0xa000);
    let copied_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(target)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(target, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("copied minor GC plan builds");
    let copied_relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &copied_plan,
        &[MinorGcRelocationDestination::new(
            target,
            copied_destination,
        )],
    )
    .expect("copied relocation plan builds");
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");
    card_table
        .mark_source(source)
        .expect("source card marks dirty");
    let source_fields = [ResolvedValueGeneration::young(target)];
    let old_fields = [MinorGcOldObjectFields::new(
        source,
        HeapGeneration::Old,
        &source_fields,
    )];
    let old_field_rescan = MinorGcOldFieldRescanPlan::from_dirty_cards(
        card_table.snapshot(),
        &old_fields,
        &copied_relocation_plan,
    )
    .expect("old-field rescan builds");
    let promoted_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(target)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(target, 1)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("promoted minor GC plan builds");
    let promoted_relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &promoted_plan,
        &[MinorGcRelocationDestination::new(
            target,
            promoted_destination,
        )],
    )
    .expect("promoted relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(
        &promoted_relocation_plan,
        &[NurseryObjectLayout::new(target, 8, 8)],
    )
    .expect("object-copy plan builds");
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
            .expect("forwarding plan builds");

    assert_eq!(
        MinorGcCommitPlan::from_parts_with_old_field_rescan(
            object_copies,
            forwarding_pointers,
            MinorGcReferenceRewritePlan::default(),
            MinorGcRememberedSetRefreshPlan::default(),
            &old_field_rescan,
        ),
        Err(GenerationalGcError::MinorGcCommitOldFieldRescanMismatch {
            original: RememberedEdge::new(source, target),
            expected: MinorGcRememberedSetRefreshAction::DropPromoted {
                destination: promoted_destination,
            },
            actual: MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                refreshed: RememberedEdge::new(source, copied_destination),
            },
        })
    );
}
