//! GC-planning unit tests, part 1 of 5 (RFC-0007 §2 split, #9).
//!
//! Move-only line-boundary split of `gc/tests.rs`; no test changed.

use super::super::*;
use super::address;

#[test]
fn heap_addresses_reject_null_and_low_pointer_tags() {
    assert_eq!(GcHeapAddress::new(0), Err(GenerationalGcError::NullAddress));
    assert_eq!(
        GcHeapAddress::new(0b1010),
        Err(GenerationalGcError::LowTagBitsPresent {
            address_bits: 0b1010,
        })
    );
    assert_eq!(address(0x1000).address_bits(), 0x1000);
}

#[test]
fn one_shot_tier_disables_thunk_resolve_write_barrier() {
    let write = ThunkResolveWrite::new(
        address(0x1000),
        HeapGeneration::Old,
        ResolvedValueGeneration::young(address(0x2000)),
    );

    let action = classify_thunk_resolve_write_barrier(GenerationalGcTier::OneShotArena, write);

    assert_eq!(action, ThunkResolveWriteBarrier::Disabled);
    assert!(action.permits_unrecorded_publish());
}

#[test]
fn daemon_tier_remembers_old_to_young_thunk_resolutions() {
    let thunk = address(0x1000);
    let value = address(0x2000);
    let write = ThunkResolveWrite::new(
        thunk,
        HeapGeneration::Old,
        ResolvedValueGeneration::young(value),
    );

    let action =
        classify_thunk_resolve_write_barrier(GenerationalGcTier::DaemonGenerational, write);

    assert_eq!(
        action,
        ThunkResolveWriteBarrier::Remember {
            edge: RememberedEdge::new(thunk, value),
        }
    );
    assert!(!action.permits_unrecorded_publish());
}

#[test]
fn daemon_tier_remembers_permanent_to_young_thunk_resolutions() {
    let thunk = address(0x3000);
    let value = address(0x4000);
    let write = ThunkResolveWrite::new(
        thunk,
        HeapGeneration::Permanent,
        ResolvedValueGeneration::young(value),
    );

    assert_eq!(
        classify_thunk_resolve_write_barrier(GenerationalGcTier::DaemonGenerational, write),
        ThunkResolveWriteBarrier::Remember {
            edge: RememberedEdge::new(thunk, value),
        }
    );
}

#[test]
fn daemon_tier_skips_young_sources_and_non_young_targets() {
    let old_value = ResolvedValueGeneration::old(address(0x3000));
    let permanent_value = ResolvedValueGeneration::permanent(address(0x4000));
    for write in [
        ThunkResolveWrite::new(
            address(0x1000),
            HeapGeneration::Young,
            ResolvedValueGeneration::young(address(0x2000)),
        ),
        ThunkResolveWrite::new(address(0x1000), HeapGeneration::Old, old_value),
        ThunkResolveWrite::new(address(0x1000), HeapGeneration::Old, permanent_value),
        ThunkResolveWrite::new(
            address(0x1000),
            HeapGeneration::Permanent,
            ResolvedValueGeneration::Inline,
        ),
    ] {
        let action =
            classify_thunk_resolve_write_barrier(GenerationalGcTier::DaemonGenerational, write);
        assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
        assert!(action.permits_unrecorded_publish());
    }
}

#[test]
fn remembered_set_deduplicates_recorded_edges() {
    let edge = RememberedEdge::new(address(0x1000), address(0x2000));
    let mut set = RememberedSet::new();

    assert_eq!(
        set.record(edge).expect("edge records"),
        RememberedSetUpdate::Inserted
    );
    assert_eq!(
        set.record(edge).expect("duplicate edge is accepted"),
        RememberedSetUpdate::AlreadyPresent
    );

    assert_eq!(set.edges(), &[edge]);
    assert_eq!(set.len(), 1);
    assert!(!set.is_empty());
}

#[test]
fn remembered_set_try_clone_preserves_epoch_and_edges() {
    let epoch = RememberedSetEpoch::new(11);
    let first = RememberedEdge::new(address(0x1000), address(0x2000));
    let second = RememberedEdge::new(address(0x3000), address(0x4000));
    let mut set = RememberedSet::with_epoch(epoch);
    set.record(first).expect("first edge records");
    set.record(second).expect("second edge records");

    let cloned = set.try_clone().expect("remembered set clones");

    assert_eq!(cloned.epoch(), epoch);
    assert_eq!(cloned.edges(), &[first, second]);
    assert_eq!(cloned, set);
}

#[test]
fn remembered_set_snapshots_carry_collection_epoch() {
    let epoch = RememberedSetEpoch::new(7);
    let edge = RememberedEdge::new(address(0x1000), address(0x2000));
    let mut set = RememberedSet::with_epoch(epoch);
    set.record(edge).expect("edge records");

    let snapshot = set.snapshot();

    assert_eq!(set.epoch(), epoch);
    assert_eq!(snapshot.epoch(), epoch);
    assert_eq!(snapshot.edges(), &[edge]);
    assert_eq!(epoch.value(), 7);
    assert_eq!(epoch.checked_next(), Ok(RememberedSetEpoch::new(8)));
    assert_eq!(
        RememberedSetEpoch::new(u64::MAX).checked_next(),
        Err(GenerationalGcError::RememberedSetEpochOverflow)
    );
}

#[test]
fn card_table_validates_card_size_and_deduplicates_dirty_cards() {
    assert_eq!(
        GcCardTable::new(0),
        Err(GenerationalGcError::InvalidGcCardSize { card_size_bytes: 0 })
    );
    assert_eq!(
        GcCardTable::new(768),
        Err(GenerationalGcError::InvalidGcCardSize {
            card_size_bytes: 768,
        })
    );

    let mut table = GcCardTable::new(0x1000).expect("card table builds");
    let first = address(0x2000);
    let same_card = address(0x2800);
    let second = address(0x3000);

    assert_eq!(table.card_size_bytes(), 0x1000);
    assert_eq!(
        table.mark_source(first).expect("first card marks"),
        GcCardTableUpdate::MarkedDirty {
            card: GcDirtyCard::new(2, first),
        }
    );
    assert_eq!(
        table.mark_source(same_card).expect("same card is accepted"),
        GcCardTableUpdate::AlreadyDirty {
            card: GcDirtyCard::new(2, first),
        }
    );
    assert_eq!(
        table.mark_source(second).expect("second card marks"),
        GcCardTableUpdate::MarkedDirty {
            card: GcDirtyCard::new(3, second),
        }
    );
    assert_eq!(
        table.dirty_cards(),
        &[GcDirtyCard::new(2, first), GcDirtyCard::new(3, second)]
    );
    assert_eq!(table.len(), 2);
    assert!(!table.is_empty());
    assert_eq!(table.try_clone().expect("card table clones"), table);

    let clear_report = table.clear_dirty_cards();
    assert_eq!(clear_report.dirty_cards(), 2);
    assert!(table.is_empty());
}

#[test]
fn card_table_snapshot_covers_dirty_source_cards() {
    let mut table = GcCardTable::new(0x1000).expect("card table builds");
    let source = address(0x2000);
    let same_card = address(0x2f00);
    let clean_card = address(0x3000);
    table.mark_source(source).expect("source card marks");

    let snapshot = table.snapshot();

    assert_eq!(snapshot.card_size_bytes(), 0x1000);
    assert_eq!(snapshot.dirty_cards(), &[GcDirtyCard::new(2, source)]);
    assert_eq!(snapshot.card_index_for_source(same_card), 2);
    assert!(snapshot.covers_source(source));
    assert!(snapshot.covers_source(same_card));
    assert!(!snapshot.covers_source(clean_card));
}

#[test]
fn record_thunk_resolve_write_barrier_records_only_required_edges() {
    let edge = RememberedEdge::new(address(0x1000), address(0x2000));
    let write = ThunkResolveWrite::new(
        edge.source(),
        HeapGeneration::Old,
        ResolvedValueGeneration::young(edge.target()),
    );
    let mut set = RememberedSet::new();

    let action = record_thunk_resolve_write_barrier(
        GenerationalGcTier::DaemonGenerational,
        write,
        &mut set,
    )
    .expect("barrier records");

    assert_eq!(action, ThunkResolveWriteBarrier::Remember { edge });
    assert_eq!(set.edges(), &[edge]);

    let no_barrier = ThunkResolveWrite::new(
        address(0x3000),
        HeapGeneration::Young,
        ResolvedValueGeneration::young(address(0x4000)),
    );
    let action = record_thunk_resolve_write_barrier(
        GenerationalGcTier::DaemonGenerational,
        no_barrier,
        &mut set,
    )
    .expect("non-barrier write succeeds");

    assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
    assert_eq!(set.edges(), &[edge]);
}

#[test]
fn record_thunk_resolve_write_barrier_marks_only_required_cards() {
    let edge = RememberedEdge::new(address(0x1000), address(0x2000));
    let write = ThunkResolveWrite::new(
        edge.source(),
        HeapGeneration::Permanent,
        ResolvedValueGeneration::young(edge.target()),
    );
    let mut set = RememberedSet::new();
    let mut card_table = GcCardTable::new(0x1000).expect("card table builds");

    let action = record_thunk_resolve_write_barrier_with_card_table(
        GenerationalGcTier::DaemonGenerational,
        write,
        &mut set,
        &mut card_table,
    )
    .expect("barrier records");

    assert_eq!(action, ThunkResolveWriteBarrier::Remember { edge });
    assert_eq!(set.edges(), &[edge]);
    assert_eq!(
        card_table.dirty_cards(),
        &[GcDirtyCard::new(1, edge.source())]
    );

    let no_barrier = ThunkResolveWrite::new(
        address(0x3000),
        HeapGeneration::Permanent,
        ResolvedValueGeneration::old(address(0x4000)),
    );
    let action = record_thunk_resolve_write_barrier_with_card_table(
        GenerationalGcTier::DaemonGenerational,
        no_barrier,
        &mut set,
        &mut card_table,
    )
    .expect("non-barrier write succeeds");

    assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
    assert_eq!(set.edges(), &[edge]);
    assert_eq!(
        card_table.dirty_cards(),
        &[GcDirtyCard::new(1, edge.source())]
    );
}

#[test]
fn card_mark_failure_rolls_back_new_remembered_edge() {
    let edge = RememberedEdge::new(address(0x1000), address(0x2000));
    let write = ThunkResolveWrite::new(
        edge.source(),
        HeapGeneration::Old,
        ResolvedValueGeneration::young(edge.target()),
    );
    let mut set = RememberedSet::new();
    let error = GenerationalGcError::GcCardTableAllocationFailed { cards: 1 };

    let result = record_thunk_resolve_write_barrier_with_card_marker(
        GenerationalGcTier::DaemonGenerational,
        write,
        &mut set,
        |_| Err(error.clone()),
    );

    assert_eq!(result, Err(error));
    assert!(set.is_empty());
}

#[test]
fn minor_gc_plan_rejects_remembered_set_epoch_mismatches() {
    let young = address(0x1000);
    let set = RememberedSet::with_epoch(RememberedSetEpoch::new(3));

    assert_eq!(
        MinorGcPlan::from_roots_and_remembered(
            [ResolvedValueGeneration::young(young)],
            set.snapshot(),
            RememberedSetEpoch::new(4),
            &[NurseryObjectAge::new(young, 0)],
            MinorGcPromotionPolicy::new(2),
        ),
        Err(GenerationalGcError::RememberedSetEpochMismatch {
            expected: RememberedSetEpoch::new(4),
            actual: RememberedSetEpoch::new(3),
        })
    );
}

#[test]
fn minor_gc_plan_accepts_non_default_matching_remembered_set_epoch() {
    let young = address(0x1000);
    let remembered = address(0x2000);
    let mut set = RememberedSet::with_epoch(RememberedSetEpoch::new(9));
    set.record(RememberedEdge::new(address(0x3000), remembered))
        .expect("remembered edge records");

    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        set.snapshot(),
        RememberedSetEpoch::new(9),
        &[
            NurseryObjectAge::new(young, 0),
            NurseryObjectAge::new(remembered, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("matching non-default epoch plans");

    assert_eq!(plan.survivors().len(), 2);
    assert_eq!(plan.survivors()[0].address(), young);
    assert_eq!(plan.survivors()[1].address(), remembered);
}

#[test]
fn minor_gc_plan_uses_young_roots_and_remembered_targets_only() {
    let root = address(0x1000);
    let remembered = address(0x2000);
    let ignored_old = address(0x3000);
    let ignored_permanent = address(0x4000);
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(address(0x5000), remembered))
        .expect("remembered edge records");
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::young(root),
            ResolvedValueGeneration::old(ignored_old),
            ResolvedValueGeneration::permanent(ignored_permanent),
        ],
        remembered_set.snapshot(),
        remembered_set.epoch(),
        &[
            NurseryObjectAge::new(root, 0),
            NurseryObjectAge::new(remembered, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    assert_eq!(plan.len(), 2);
    assert!(!plan.is_empty());
    assert_eq!(plan.survivors()[0].address(), root);
    assert_eq!(plan.survivors()[1].address(), remembered);
    assert!(
        plan.survivors()
            .iter()
            .all(|survivor| survivor.action() == MinorGcSurvivorAction::CopyToNursery)
    );
}

#[test]
fn minor_gc_plan_deduplicates_roots_and_distinct_remembered_sources() {
    let young = address(0x1000);
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(address(0x3000), young))
        .expect("remembered edge records");
    remembered_set
        .record(RememberedEdge::new(address(0x4000), young))
        .expect("same young target from a distinct source records");

    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(young),
            ResolvedValueGeneration::young(young),
        ],
        remembered_set.snapshot(),
        remembered_set.epoch(),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    assert_eq!(plan.survivors().len(), 1);
    assert_eq!(plan.survivors()[0].address(), young);
}

#[test]
fn minor_gc_plan_expands_transitive_young_fields() {
    let root = address(0x1000);
    let remembered = address(0x2000);
    let child = address(0x3000);
    let grandchild = address(0x4000);
    let remembered_child = address(0x5000);
    let ignored_old = address(0x6000);
    let ignored_permanent = address(0x7000);
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(11));
    remembered_set
        .record(RememberedEdge::new(address(0x8000), remembered))
        .expect("remembered edge records");
    let root_fields = [
        ResolvedValueGeneration::Inline,
        ResolvedValueGeneration::young(child),
        ResolvedValueGeneration::old(ignored_old),
        ResolvedValueGeneration::permanent(ignored_permanent),
    ];
    let remembered_fields = [ResolvedValueGeneration::young(remembered_child)];
    let child_fields = [ResolvedValueGeneration::young(grandchild)];
    let remembered_child_fields = [ResolvedValueGeneration::young(root)];
    let grandchild_fields = [ResolvedValueGeneration::young(root)];
    let plan = MinorGcPlan::from_roots_remembered_and_fields(
        [ResolvedValueGeneration::young(root)],
        remembered_set.snapshot(),
        remembered_set.epoch(),
        &[
            NurseryObjectAge::new(root, 0),
            NurseryObjectAge::new(remembered, 0),
            NurseryObjectAge::new(child, 1),
            NurseryObjectAge::new(remembered_child, 1),
            NurseryObjectAge::new(grandchild, 1),
        ],
        &[
            NurseryObjectFields::new(root, &root_fields),
            NurseryObjectFields::new(remembered, &remembered_fields),
            NurseryObjectFields::new(child, &child_fields),
            NurseryObjectFields::new(remembered_child, &remembered_child_fields),
            NurseryObjectFields::new(grandchild, &grandchild_fields),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("expanded minor GC plan builds");

    assert_eq!(plan.survivors().len(), 5);
    assert_eq!(plan.survivors()[0].address(), root);
    assert_eq!(plan.survivors()[1].address(), remembered);
    assert_eq!(plan.survivors()[2].address(), child);
    assert_eq!(plan.survivors()[3].address(), remembered_child);
    assert_eq!(plan.survivors()[4].address(), grandchild);
    assert_eq!(
        plan.survivors()[2].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        plan.survivors()[3].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        plan.survivors()[4].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
}

#[test]
fn minor_gc_field_expansion_rejects_missing_or_duplicate_field_metadata() {
    let young = address(0x1000);
    assert_eq!(
        MinorGcPlan::from_roots_remembered_and_fields(
            [ResolvedValueGeneration::young(young)],
            RememberedSet::new().snapshot(),
            RememberedSetEpoch::new(0),
            &[NurseryObjectAge::new(young, 0)],
            &[],
            MinorGcPromotionPolicy::new(2),
        ),
        Err(GenerationalGcError::MissingNurseryObjectFields { address: young })
    );

    assert_eq!(
        MinorGcPlan::from_roots_remembered_and_fields(
            [ResolvedValueGeneration::young(young)],
            RememberedSet::new().snapshot(),
            RememberedSetEpoch::new(0),
            &[NurseryObjectAge::new(young, 0)],
            &[
                NurseryObjectFields::new(young, &[]),
                NurseryObjectFields::new(young, &[]),
            ],
            MinorGcPromotionPolicy::new(2),
        ),
        Err(GenerationalGcError::DuplicateNurseryObjectFields { address: young })
    );
}

#[test]
fn minor_gc_plan_applies_age_based_promotion_policy() {
    let copy = address(0x1000);
    let promote = address(0x2000);
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

    assert_eq!(plan.survivors()[0].previous_survivals(), 0);
    assert_eq!(plan.survivors()[0].next_survivals(), 1);
    assert_eq!(
        plan.survivors()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(plan.survivors()[1].previous_survivals(), 1);
    assert_eq!(plan.survivors()[1].next_survivals(), 2);
    assert_eq!(
        plan.survivors()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
}

#[test]
fn minor_gc_destination_allocation_plan_splits_copy_and_promote_bytes() {
    let copy = address(0x1000);
    let promote = address(0x2000);
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

    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(promote, 40, 16),
            NurseryObjectLayout::new(copy, 24, 8),
        ],
    )
    .expect("allocation plan builds");

    assert_eq!(allocation_plan.len(), 2);
    assert!(!allocation_plan.is_empty());
    assert_eq!(allocation_plan.nursery_bytes(), 24);
    assert_eq!(allocation_plan.old_bytes(), 40);
    assert_eq!(allocation_plan.total_bytes(), 64);
    assert_eq!(allocation_plan.allocations()[0].source(), copy);
    assert_eq!(
        allocation_plan.allocations()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        allocation_plan.allocations()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(allocation_plan.allocations()[0].size_bytes(), 24);
    assert_eq!(allocation_plan.allocations()[0].align(), 8);
    assert_eq!(allocation_plan.allocations()[1].source(), promote);
    assert_eq!(
        allocation_plan.allocations()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        allocation_plan.allocations()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(allocation_plan.allocations()[1].size_bytes(), 40);
    assert_eq!(allocation_plan.allocations()[1].align(), 16);
    assert_eq!(
        allocation_plan.allocations()[1].survivor(),
        plan.survivors()[1]
    );
}

#[test]
fn minor_gc_destination_allocation_plan_rejects_invalid_layout_metadata() {
    let young = address(0x1000);
    let other = address(0x2000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(&plan, &[]),
        Err(GenerationalGcError::MissingNurseryObjectLayout { address: young })
    );
    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(
            &plan,
            &[
                NurseryObjectLayout::new(young, 8, 8),
                NurseryObjectLayout::new(young, 16, 8),
            ],
        ),
        Err(GenerationalGcError::DuplicateNurseryObjectLayout { address: young })
    );
    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(
            &plan,
            &[NurseryObjectLayout::new(young, 0, 8)],
        ),
        Err(GenerationalGcError::InvalidNurseryObjectSize {
            address: young,
            size_bytes: 0,
        })
    );
    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(
            &plan,
            &[NurseryObjectLayout::new(young, 8, 3)],
        ),
        Err(GenerationalGcError::InvalidNurseryObjectAlignment {
            address: young,
            align: 3,
        })
    );
    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(
            &plan,
            &[
                NurseryObjectLayout::new(young, 8, 8),
                NurseryObjectLayout::new(other, 16, 8),
            ],
        ),
        Err(GenerationalGcError::StaleNurseryObjectLayout { address: other })
    );
}

#[test]
fn minor_gc_destination_allocation_plan_rejects_byte_overflow() {
    let first = address(0x1000);
    let second = address(0x2000);
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

    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(
            &plan,
            &[
                NurseryObjectLayout::new(first, usize::MAX, 8),
                NurseryObjectLayout::new(second, 1, 8),
            ],
        ),
        Err(GenerationalGcError::MinorGcDestinationBytesOverflow {
            generation: HeapGeneration::Young,
        })
    );

    let split_plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("split minor GC plan builds");
    assert_eq!(
        MinorGcDestinationAllocationPlan::from_minor_gc_plan(
            &split_plan,
            &[
                NurseryObjectLayout::new(first, usize::MAX, 8),
                NurseryObjectLayout::new(second, usize::MAX, 8),
            ],
        ),
        Err(GenerationalGcError::MinorGcDestinationTotalBytesOverflow)
    );
}

#[test]
fn minor_gc_destination_placement_plan_aligns_offsets_by_generation() {
    let first_copy = address(0x1000);
    let promote = address(0x2000);
    let second_copy = address(0x3000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first_copy),
            ResolvedValueGeneration::young(promote),
            ResolvedValueGeneration::young(second_copy),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first_copy, 0),
            NurseryObjectAge::new(promote, 1),
            NurseryObjectAge::new(second_copy, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(second_copy, 8, 16),
            NurseryObjectLayout::new(promote, 40, 16),
            NurseryObjectLayout::new(first_copy, 24, 8),
        ],
    )
    .expect("allocation plan builds");

    let placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)
            .expect("placement plan builds");

    assert_eq!(placement_plan.len(), 3);
    assert!(!placement_plan.is_empty());
    assert_eq!(placement_plan.nursery_reserved_bytes(), 40);
    assert_eq!(placement_plan.old_reserved_bytes(), 40);
    assert_eq!(placement_plan.total_reserved_bytes(), 80);
    assert_eq!(placement_plan.placements()[0].source(), first_copy);
    assert_eq!(
        placement_plan.placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(placement_plan.placements()[0].offset_bytes(), 0);
    assert_eq!(placement_plan.placements()[0].end_offset_bytes(), 24);
    assert_eq!(placement_plan.placements()[1].source(), promote);
    assert_eq!(
        placement_plan.placements()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(placement_plan.placements()[1].offset_bytes(), 0);
    assert_eq!(placement_plan.placements()[1].end_offset_bytes(), 40);
    assert_eq!(placement_plan.placements()[2].source(), second_copy);
    assert_eq!(
        placement_plan.placements()[2].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(placement_plan.placements()[2].offset_bytes(), 32);
    assert_eq!(placement_plan.placements()[2].end_offset_bytes(), 40);
    assert_eq!(placement_plan.placements()[2].size_bytes(), 8);
    assert_eq!(placement_plan.placements()[2].align(), 16);
    assert_eq!(
        placement_plan.placements()[2].allocation(),
        allocation_plan.allocations()[2]
    );
    assert_eq!(
        placement_plan.placements()[2].survivor(),
        plan.survivors()[2]
    );
}

#[test]
fn minor_gc_destination_placement_plan_rejects_reserved_byte_overflow() {
    let first = address(0x1000);
    let second = address(0x2000);
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
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, usize::MAX - 1, 1),
            NurseryObjectLayout::new(second, 1, 8),
        ],
    )
    .expect("allocation plan builds");

    assert_eq!(
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan),
        Err(
            GenerationalGcError::MinorGcDestinationPlacementBytesOverflow {
                generation: HeapGeneration::Young,
            }
        )
    );

    let promote = address(0x3000);
    let split_plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("split minor GC plan builds");
    let split_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &split_plan,
        &[
            NurseryObjectLayout::new(first, usize::MAX - 2, 1),
            NurseryObjectLayout::new(second, 1, 2),
            NurseryObjectLayout::new(promote, 1, 1),
        ],
    )
    .expect("split allocation plan builds");

    assert_eq!(
        MinorGcDestinationPlacementPlan::from_allocation_plan(&split_allocation_plan),
        Err(GenerationalGcError::MinorGcDestinationPlacementTotalBytesOverflow)
    );
}
