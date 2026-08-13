//! GC-planning unit tests, part 5 of 5 (RFC-0007 §2 split, #9).
//!
//! Move-only line-boundary split of `gc/tests.rs`; no test changed.

use super::super::*;
use super::address;

#[test]
fn minor_gc_commit_plan_rejects_stale_buffers_without_partial_writes() {
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
            NurseryObjectLayout::new(copy, 4, 4),
            NurseryObjectLayout::new(promote, 4, 4),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_pointers = MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
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
        commit_plan.apply_to_buffers(MinorGcCommitBuffers::with_card_table(
            &mut object_byte_copies,
            &mut forwarding_slots,
            &mut references,
            &mut stale_remembered_set,
            &mut card_table,
        )),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch {
                expected: RememberedSetEpoch::new(7),
                actual: RememberedSetEpoch::new(8),
            }
        )
    );
    assert_eq!(object_byte_copies[0].destination_bytes(), [0; 4]);
    assert_eq!(object_byte_copies[1].destination_bytes(), [0; 4]);
    assert!(forwarding_slots[0].is_empty());
    assert!(forwarding_slots[1].is_empty());
    assert_eq!(references, original_references);
    assert_eq!(stale_remembered_set, unchanged_stale_remembered_set);
    assert_eq!(card_table, unchanged_card_table);
}

#[test]
fn minor_gc_commit_plan_rejects_inconsistent_subplans() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0xa000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ],
    )
    .expect("relocation plan builds");
    let object_copies = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(first, 8, 8),
            NurseryObjectLayout::new(second, 8, 8),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_pointers = MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
        .expect("forwarding plan builds");
    let reference_rewrites = MinorGcReferenceRewritePlan::from_references(
        &relocation_plan,
        [ResolvedValueGeneration::young(first)],
    )
    .expect("reference rewrite plan builds");

    let publication_commit_plan = MinorGcCommitPlan::from_parts(
        object_copies.clone(),
        forwarding_pointers.clone(),
        MinorGcReferenceRewritePlan::default(),
        MinorGcRememberedSetRefreshPlan::default(),
    )
    .expect("publication commit plan builds");
    let stale_edge = RememberedEdge::new(address(0x3000), first);
    let mut stale_remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(1));
    stale_remembered_set
        .record(stale_edge)
        .expect("stale remembered edge records");
    let unchanged_stale_remembered_set = stale_remembered_set.clone();
    assert_eq!(
        publication_commit_plan.publish_next_remembered_set(&mut stale_remembered_set),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch {
                expected: RememberedSetEpoch::new(0),
                actual: RememberedSetEpoch::new(1),
            }
        )
    );
    assert_eq!(stale_remembered_set, unchanged_stale_remembered_set);

    let publication_commit_plan = MinorGcCommitPlan::from_parts(
        object_copies.clone(),
        forwarding_pointers.clone(),
        MinorGcReferenceRewritePlan::default(),
        MinorGcRememberedSetRefreshPlan::default(),
    )
    .expect("publication commit plan builds");
    let mut changed_same_epoch_remembered_set = RememberedSet::new();
    changed_same_epoch_remembered_set
        .record(stale_edge)
        .expect("same-epoch remembered edge records");
    let unchanged_changed_same_epoch_remembered_set = changed_same_epoch_remembered_set.clone();
    assert_eq!(
        publication_commit_plan.publish_next_remembered_set(&mut changed_same_epoch_remembered_set),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationLengthMismatch {
                expected: 0,
                actual: 1,
            }
        )
    );
    assert_eq!(
        changed_same_epoch_remembered_set,
        unchanged_changed_same_epoch_remembered_set
    );

    let expected_publication_edge = RememberedEdge::new(address(0x4000), first);
    let mut source_remembered_set = RememberedSet::new();
    source_remembered_set
        .record(expected_publication_edge)
        .expect("source remembered edge records");
    let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        source_remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("remembered-set refresh plan builds");
    let publication_commit_plan = MinorGcCommitPlan::from_parts(
        object_copies.clone(),
        forwarding_pointers.clone(),
        MinorGcReferenceRewritePlan::default(),
        remembered_set_refresh,
    )
    .expect("publication commit plan builds");
    let actual_publication_edge = RememberedEdge::new(address(0x5000), first);
    let mut changed_same_length_remembered_set = RememberedSet::new();
    changed_same_length_remembered_set
        .record(actual_publication_edge)
        .expect("same-length remembered edge records");
    let unchanged_changed_same_length_remembered_set = changed_same_length_remembered_set.clone();
    assert_eq!(
        publication_commit_plan
            .publish_next_remembered_set(&mut changed_same_length_remembered_set),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationEdgeMismatch {
                index: 0,
                expected: expected_publication_edge,
                actual: actual_publication_edge,
            }
        )
    );
    assert_eq!(
        changed_same_length_remembered_set,
        unchanged_changed_same_length_remembered_set
    );

    assert_eq!(
        MinorGcCommitPlan::from_parts(
            object_copies.clone(),
            MinorGcForwardingPointerPlan::default(),
            MinorGcReferenceRewritePlan::default(),
            MinorGcRememberedSetRefreshPlan::default(),
        ),
        Err(
            GenerationalGcError::MinorGcCommitForwardingPointerLengthMismatch {
                copies: 2,
                pointers: 0,
            }
        )
    );

    let reversed_forwarding_pointers = MinorGcForwardingPointerPlan {
        pointers: vec![
            forwarding_pointers.pointers()[1],
            forwarding_pointers.pointers()[0],
        ],
    };
    assert_eq!(
        MinorGcCommitPlan::from_parts(
            object_copies.clone(),
            reversed_forwarding_pointers,
            MinorGcReferenceRewritePlan::default(),
            MinorGcRememberedSetRefreshPlan::default(),
        ),
        Err(
            GenerationalGcError::MinorGcCommitForwardingPointerMismatch {
                index: 0,
                expected: forwarding_pointers.pointers()[0],
                actual: forwarding_pointers.pointers()[1],
            }
        )
    );

    assert_eq!(
        MinorGcCommitPlan::from_parts(
            MinorGcObjectCopyPlan::default(),
            MinorGcForwardingPointerPlan::default(),
            reference_rewrites.clone(),
            MinorGcRememberedSetRefreshPlan::default(),
        ),
        Err(GenerationalGcError::MinorGcCommitReferenceRewriteSourceMissing { address: first })
    );

    let mut mismatched_reference_rewrites = reference_rewrites.clone();
    mismatched_reference_rewrites.rewrites[0].destination = second_destination;
    assert_eq!(
        MinorGcCommitPlan::from_parts(
            object_copies.clone(),
            forwarding_pointers.clone(),
            mismatched_reference_rewrites,
            MinorGcRememberedSetRefreshPlan::default(),
        ),
        Err(GenerationalGcError::MinorGcCommitReferenceRewriteMismatch {
            slot: 0,
            address: first,
            expected: ResolvedValueGeneration::young(first_destination),
            actual: ResolvedValueGeneration::young(second_destination),
        })
    );

    let remembered_source = address(0x3000);
    let retained_uncopied_refresh = MinorGcRememberedSetRefreshPlan {
        source_epoch: RememberedSetEpoch::new(0),
        refreshes: vec![MinorGcRememberedSetRefresh {
            original: RememberedEdge::new(remembered_source, first),
            action: MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                refreshed: RememberedEdge::new(remembered_source, first_destination),
            },
        }],
    };
    assert_eq!(
        MinorGcCommitPlan::from_parts(
            MinorGcObjectCopyPlan::default(),
            MinorGcForwardingPointerPlan::default(),
            MinorGcReferenceRewritePlan::default(),
            retained_uncopied_refresh,
        ),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetRefreshMismatch {
                original: RememberedEdge::new(remembered_source, first),
                expected: MinorGcRememberedSetRefreshAction::DropDead,
                actual: MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                    refreshed: RememberedEdge::new(remembered_source, first_destination),
                },
            }
        )
    );

    let promoted_copied_refresh = MinorGcRememberedSetRefreshPlan {
        source_epoch: RememberedSetEpoch::new(0),
        refreshes: vec![MinorGcRememberedSetRefresh {
            original: RememberedEdge::new(remembered_source, first),
            action: MinorGcRememberedSetRefreshAction::DropPromoted {
                destination: first_destination,
            },
        }],
    };
    assert_eq!(
        MinorGcCommitPlan::from_parts(
            object_copies.clone(),
            forwarding_pointers.clone(),
            MinorGcReferenceRewritePlan::default(),
            promoted_copied_refresh,
        ),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetRefreshMismatch {
                original: RememberedEdge::new(remembered_source, first),
                expected: MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                    refreshed: RememberedEdge::new(remembered_source, first_destination),
                },
                actual: MinorGcRememberedSetRefreshAction::DropPromoted {
                    destination: first_destination,
                },
            }
        )
    );

    let dropped_copied_refresh = MinorGcRememberedSetRefreshPlan {
        source_epoch: RememberedSetEpoch::new(0),
        refreshes: vec![MinorGcRememberedSetRefresh {
            original: RememberedEdge::new(remembered_source, first),
            action: MinorGcRememberedSetRefreshAction::DropDead,
        }],
    };
    assert_eq!(
        MinorGcCommitPlan::from_parts(
            object_copies.clone(),
            forwarding_pointers,
            MinorGcReferenceRewritePlan::default(),
            dropped_copied_refresh,
        ),
        Err(
            GenerationalGcError::MinorGcCommitRememberedSetRefreshMismatch {
                original: RememberedEdge::new(remembered_source, first),
                expected: MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                    refreshed: RememberedEdge::new(remembered_source, first_destination),
                },
                actual: MinorGcRememberedSetRefreshAction::DropDead,
            }
        )
    );

    let max_epoch_refresh = MinorGcRememberedSetRefreshPlan {
        source_epoch: RememberedSetEpoch::new(u64::MAX),
        refreshes: vec![],
    };
    assert_eq!(
        MinorGcCommitPlan::from_parts(
            MinorGcObjectCopyPlan::default(),
            MinorGcForwardingPointerPlan::default(),
            MinorGcReferenceRewritePlan::default(),
            max_epoch_refresh,
        ),
        Err(GenerationalGcError::RememberedSetEpochOverflow)
    );
}

#[test]
fn zero_survival_threshold_promotes_every_minor_gc_survivor() {
    let young = address(0x1000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(0),
    )
    .expect("minor GC plan builds");

    assert_eq!(plan.survivors()[0].next_survivals(), 1);
    assert_eq!(
        plan.survivors()[0].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
}

#[test]
fn minor_gc_plan_rejects_missing_or_duplicate_nursery_metadata() {
    let young = address(0x1000);
    assert_eq!(
        MinorGcPlan::from_roots_and_remembered(
            [ResolvedValueGeneration::young(young)],
            RememberedSet::new().snapshot(),
            RememberedSetEpoch::new(0),
            &[],
            MinorGcPromotionPolicy::new(2),
        ),
        Err(GenerationalGcError::MissingNurseryObjectAge { address: young })
    );
    assert_eq!(
        MinorGcPlan::from_roots_and_remembered(
            [ResolvedValueGeneration::young(young)],
            RememberedSet::new().snapshot(),
            RememberedSetEpoch::new(0),
            &[
                NurseryObjectAge::new(young, 0),
                NurseryObjectAge::new(young, 1)
            ],
            MinorGcPromotionPolicy::new(2),
        ),
        Err(GenerationalGcError::DuplicateNurseryObjectAge { address: young })
    );
}
