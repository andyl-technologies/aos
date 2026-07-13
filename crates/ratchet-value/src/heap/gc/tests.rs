//! Unit tests for the generational-GC planning surface (RFC-0007 §2 split, #9).
//!
//! Move-only extraction of the trailing `#[cfg(test)] mod tests` from `gc.rs`,
//! de-indented; no test was changed.

use super::*;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("aligned address")
}

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

#[test]
fn minor_gc_destination_placement_plan_rejects_invalid_alignment_metadata() {
    let young = address(0x1000);
    let survivor = MinorGcSurvivor {
        address: young,
        previous_survivals: 0,
        next_survivals: 1,
        action: MinorGcSurvivorAction::CopyToNursery,
    };
    let allocation_plan = MinorGcDestinationAllocationPlan {
        allocations: vec![MinorGcDestinationAllocation {
            survivor,
            size_bytes: 8,
            align: 0,
        }],
        nursery_bytes: 8,
        old_bytes: 0,
    };

    assert_eq!(
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan),
        Err(
            GenerationalGcError::InvalidMinorGcDestinationPlacementAlignment {
                generation: HeapGeneration::Young,
                align: 0,
            }
        )
    );
}

#[test]
fn minor_gc_relocation_destination_plan_materializes_offsets_from_bases() {
    let first_copy = address(0x1000);
    let promote = address(0x2000);
    let second_copy = address(0x3000);
    let nursery_base = address(0x9000);
    let old_base = address(0xa000);
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
    let bases = MinorGcDestinationBases::new(nursery_base, old_base);

    let destination_plan =
        MinorGcRelocationDestinationPlan::from_placement_plan(&plan, &placement_plan, bases)
            .expect("relocation destination plan builds");

    assert_eq!(bases.nursery(), nursery_base);
    assert_eq!(bases.old(), old_base);
    assert_eq!(destination_plan.len(), 3);
    assert!(!destination_plan.is_empty());
    assert_eq!(destination_plan.destinations()[0].source(), first_copy);
    assert_eq!(
        destination_plan.destinations()[0].destination(),
        nursery_base
    );
    assert_eq!(destination_plan.destinations()[1].source(), promote);
    assert_eq!(destination_plan.destinations()[1].destination(), old_base);
    assert_eq!(destination_plan.destinations()[2].source(), second_copy);
    assert_eq!(
        destination_plan.destinations()[2].destination(),
        address(0x9020)
    );

    let relocation_plan = destination_plan
        .relocation_plan(&plan)
        .expect("relocation plan builds");
    assert_eq!(relocation_plan.len(), 3);
    assert_eq!(relocation_plan.relocations()[0].source(), first_copy);
    assert_eq!(relocation_plan.relocations()[0].destination(), nursery_base);
    assert_eq!(
        relocation_plan.relocations()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(relocation_plan.relocations()[1].source(), promote);
    assert_eq!(relocation_plan.relocations()[1].destination(), old_base);
    assert_eq!(
        relocation_plan.relocations()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(relocation_plan.relocations()[2].source(), second_copy);
    assert_eq!(
        relocation_plan.relocations()[2].destination(),
        address(0x9020)
    );
}

#[test]
fn minor_gc_relocation_destination_plan_rejects_bad_materialized_addresses() {
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
    let overflow_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, 8, 8),
            NurseryObjectLayout::new(second, 8, 8),
        ],
    )
    .expect("overflow allocation plan builds");
    let overflow_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&overflow_allocation_plan)
            .expect("overflow placement plan builds");
    let overflow_base = address(usize::MAX & !POINTER_TAG_MASK);

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &plan,
            &overflow_placement_plan,
            MinorGcDestinationBases::new(overflow_base, address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationAddressOverflow {
                generation: HeapGeneration::Young,
                base: overflow_base,
                offset: 8,
            }
        )
    );

    let low_tag_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, 4, 4),
            NurseryObjectLayout::new(second, 8, 4),
        ],
    )
    .expect("low-tag allocation plan builds");
    let low_tag_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&low_tag_allocation_plan)
            .expect("low-tag placement plan builds");

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &plan,
            &low_tag_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(GenerationalGcError::LowTagBitsPresent {
            address_bits: 0x9004,
        })
    );

    let misaligned_base_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, 16, 16),
            NurseryObjectLayout::new(second, 8, 8),
        ],
    )
    .expect("misaligned-base allocation plan builds");
    let misaligned_base_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&misaligned_base_allocation_plan)
            .expect("misaligned-base placement plan builds");
    let misaligned_destination = address(0x9008);

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &plan,
            &misaligned_base_placement_plan,
            MinorGcDestinationBases::new(misaligned_destination, address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: first,
                generation: HeapGeneration::Young,
                destination: misaligned_destination,
                align: 16,
            }
        )
    );
}

#[test]
fn minor_gc_relocation_destination_plan_rejects_mismatched_placement_plan() {
    let young = address(0x1000);
    let copy_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("copy minor GC plan builds");
    let promote_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 1)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("promote minor GC plan builds");
    let copy_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &copy_plan,
        &[NurseryObjectLayout::new(young, 8, 8)],
    )
    .expect("copy allocation plan builds");
    let copy_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&copy_allocation_plan)
            .expect("copy placement plan builds");

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &promote_plan,
            &copy_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
                address: young,
                expected: MinorGcSurvivorAction::PromoteToOld,
                actual: MinorGcSurvivorAction::CopyToNursery,
            }
        )
    );

    let other = address(0x2000);
    let two_survivor_plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(young),
            ResolvedValueGeneration::young(other),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(young, 0),
            NurseryObjectAge::new(other, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("two-survivor minor GC plan builds");
    let reversed_plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(other),
            ResolvedValueGeneration::young(young),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(young, 0),
            NurseryObjectAge::new(other, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("reversed minor GC plan builds");
    let reversed_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &reversed_plan,
        &[
            NurseryObjectLayout::new(young, 8, 8),
            NurseryObjectLayout::new(other, 8, 8),
        ],
    )
    .expect("reversed allocation plan builds");
    let reversed_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&reversed_allocation_plan)
            .expect("reversed placement plan builds");

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &two_survivor_plan,
            &reversed_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
                expected: young,
                actual: other,
            }
        )
    );

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &two_survivor_plan,
            &copy_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementLengthMismatch {
                survivors: 2,
                placements: 1,
            }
        )
    );
}

#[test]
fn minor_gc_relocation_plan_maps_survivors_in_frontier_order() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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
            MinorGcRelocationDestination::new(promote, promote_destination),
            MinorGcRelocationDestination::new(copy, copy_destination),
        ],
    )
    .expect("relocation plan builds");

    assert_eq!(relocation_plan.len(), 2);
    assert!(!relocation_plan.is_empty());
    assert_eq!(relocation_plan.relocations()[0].source(), copy);
    assert_eq!(
        relocation_plan.relocations()[0].destination(),
        copy_destination
    );
    assert_eq!(
        relocation_plan.relocations()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(relocation_plan.relocations()[1].source(), promote);
    assert_eq!(
        relocation_plan.relocations()[1].destination(),
        promote_destination
    );
    assert_eq!(
        relocation_plan.relocations()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        relocation_plan.relocations()[1].survivor(),
        plan.survivors()[1]
    );
}

#[test]
fn minor_gc_relocation_plan_rejects_incomplete_or_stale_metadata() {
    let young = address(0x1000);
    let other = address(0x2000);
    let destination = address(0x9000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(&plan, &[]),
        Err(GenerationalGcError::MissingMinorGcRelocationDestination { address: young })
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(young, destination),
                MinorGcRelocationDestination::new(young, address(0xa000)),
            ],
        ),
        Err(GenerationalGcError::DuplicateMinorGcRelocationSource { address: young })
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(young, destination),
                MinorGcRelocationDestination::new(other, destination),
            ],
        ),
        Err(GenerationalGcError::DuplicateMinorGcRelocationDestination {
            address: destination,
        },)
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(young, destination),
                MinorGcRelocationDestination::new(other, address(0xa000)),
            ],
        ),
        Err(GenerationalGcError::StaleMinorGcRelocationSource { address: other })
    );
}

#[test]
fn minor_gc_relocation_destination_plan_canonicalizes_explicit_destinations() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0xb000);
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
    let explicit_destinations = [
        MinorGcRelocationDestination::new(second, second_destination),
        MinorGcRelocationDestination::new(first, first_destination),
    ];

    let destination_plan =
        MinorGcRelocationDestinationPlan::from_destinations(&plan, &explicit_destinations)
            .expect("explicit destination plan builds");

    assert_eq!(
        destination_plan.destinations(),
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ]
    );
    assert_eq!(
        destination_plan
            .relocation_plan(&plan)
            .expect("relocation map rebuilds")
            .relocations()
            .iter()
            .map(|relocation| relocation.destination())
            .collect::<Vec<_>>(),
        vec![first_destination, second_destination]
    );
}

#[test]
fn minor_gc_relocation_plan_rejects_destinations_in_from_space() {
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
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(first, first),
                MinorGcRelocationDestination::new(second, address(0x9000)),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationInFromSpace {
                from: first,
                destination: first,
            }
        )
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(first, second),
                MinorGcRelocationDestination::new(second, address(0x9000)),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationInFromSpace {
                from: first,
                destination: second,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_schedules_relocations_with_layouts() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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

    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(promote, 40, 16),
            NurseryObjectLayout::new(copy, 24, 8),
        ],
    )
    .expect("object-copy plan builds");

    assert_eq!(copy_plan.len(), 2);
    assert!(!copy_plan.is_empty());
    assert_eq!(
        copy_plan.copies()[0].relocation(),
        relocation_plan.relocations()[0]
    );
    assert_eq!(copy_plan.copies()[0].source(), copy);
    assert_eq!(copy_plan.copies()[0].destination(), copy_destination);
    assert_eq!(
        copy_plan.copies()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        copy_plan.copies()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        copy_plan.copies()[0].relocated_value(),
        ResolvedValueGeneration::young(copy_destination)
    );
    assert_eq!(copy_plan.copies()[0].size_bytes(), 24);
    assert_eq!(copy_plan.copies()[0].align(), 8);
    assert_eq!(copy_plan.copies()[1].source(), promote);
    assert_eq!(copy_plan.copies()[1].destination(), promote_destination);
    assert_eq!(
        copy_plan.copies()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        copy_plan.copies()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        copy_plan.copies()[1].relocated_value(),
        ResolvedValueGeneration::old(promote_destination)
    );
    assert_eq!(copy_plan.copies()[1].size_bytes(), 40);
    assert_eq!(copy_plan.copies()[1].align(), 16);
}

#[test]
fn minor_gc_object_copy_plan_copies_bytes_into_destination_buffers() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 4, 4),
            NurseryObjectLayout::new(promote, 6, 2),
        ],
    )
    .expect("object-copy plan builds");
    let copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8, 9, 10];
    let mut copy_destination_bytes = [0; 4];
    let mut promote_destination_bytes = [0; 6];
    let mut buffers = [
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

    copy_plan
        .copy_into_buffers(&mut buffers)
        .expect("object bytes copy");

    assert_eq!(buffers[0].source(), copy);
    assert_eq!(buffers[0].destination(), copy_destination);
    assert_eq!(buffers[0].source_bytes(), copy_source);
    assert_eq!(buffers[0].destination_bytes(), copy_source);
    assert_eq!(buffers[1].source(), promote);
    assert_eq!(buffers[1].destination(), promote_destination);
    assert_eq!(buffers[1].source_bytes(), promote_source);
    assert_eq!(buffers[1].destination_bytes(), promote_source);

    let mut empty_buffers = [];
    MinorGcObjectCopyPlan::default()
        .copy_into_buffers(&mut empty_buffers)
        .expect("empty object-copy plan accepts empty buffers");
}

#[test]
fn minor_gc_object_copy_plan_rejects_stale_byte_copy_buffers() {
    let first = address(0x1000);
    let second = address(0x2000);
    let other = address(0x3000);
    let first_destination = address(0x9000);
    let second_destination = address(0xa000);
    let other_destination = address(0xb000);
    let plan = MinorGcPlan::from_roots_and_remembered(
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
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ],
    )
    .expect("relocation plan builds");
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(first, 4, 4),
            NurseryObjectLayout::new(second, 4, 4),
        ],
    )
    .expect("object-copy plan builds");
    let first_source = [1, 2, 3, 4];
    let second_source = [5, 6, 7, 8];

    let mut short_destination = [0; 4];
    let mut short_buffers = [MinorGcObjectByteCopyBuffer::new(
        first,
        first_destination,
        &first_source,
        &mut short_destination,
    )];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut short_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopyBufferLengthMismatch {
                copies: 2,
                buffers: 1,
            }
        )
    );
    assert_eq!(short_buffers[0].destination_bytes(), [0; 4]);

    let mut mismatched_first_destination = [0; 4];
    let mut mismatched_second_destination = [0; 4];
    let mut mismatched_source_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            other,
            first_destination,
            &first_source,
            &mut mismatched_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            second_destination,
            &second_source,
            &mut mismatched_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut mismatched_source_buffers),
        Err(GenerationalGcError::MinorGcObjectByteCopySourceMismatch {
            index: 0,
            expected: first,
            actual: other,
        })
    );
    assert_eq!(mismatched_source_buffers[0].destination_bytes(), [0; 4]);
    assert_eq!(mismatched_source_buffers[1].destination_bytes(), [0; 4]);

    let mut mismatched_first_destination = [0; 4];
    let mut mismatched_second_destination = [0; 4];
    let mut mismatched_destination_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            first,
            first_destination,
            &first_source,
            &mut mismatched_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            other_destination,
            &second_source,
            &mut mismatched_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut mismatched_destination_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopyDestinationMismatch {
                index: 1,
                expected: second_destination,
                actual: other_destination,
            }
        )
    );
    assert_eq!(
        mismatched_destination_buffers[0].destination_bytes(),
        [0; 4]
    );
    assert_eq!(
        mismatched_destination_buffers[1].destination_bytes(),
        [0; 4]
    );

    let short_source = [1, 2, 3];
    let mut source_length_first_destination = [0; 4];
    let mut source_length_second_destination = [0; 4];
    let mut source_length_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            first,
            first_destination,
            &short_source,
            &mut source_length_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            second_destination,
            &second_source,
            &mut source_length_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut source_length_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopySourceLengthMismatch {
                index: 0,
                address: first,
                expected: 4,
                actual: 3,
            }
        )
    );
    assert_eq!(source_length_buffers[0].destination_bytes(), [0; 4]);
    assert_eq!(source_length_buffers[1].destination_bytes(), [0; 4]);

    let mut destination_length_first_destination = [0; 4];
    let mut destination_length_second_destination = [0; 3];
    let mut destination_length_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            first,
            first_destination,
            &first_source,
            &mut destination_length_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            second_destination,
            &second_source,
            &mut destination_length_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut destination_length_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopyDestinationLengthMismatch {
                index: 1,
                address: second_destination,
                expected: 4,
                actual: 3,
            }
        )
    );
    assert_eq!(destination_length_buffers[0].destination_bytes(), [0; 4]);
    assert_eq!(destination_length_buffers[1].destination_bytes(), [0; 3]);
}

#[test]
fn minor_gc_object_copy_plan_rejects_bad_layout_metadata() {
    let young = address(0x1000);
    let other = address(0x2000);
    let destination = address(0x9000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(young, destination)],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, &[]),
        Err(GenerationalGcError::MissingNurseryObjectLayout { address: young })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(young, 8, 8),
                NurseryObjectLayout::new(young, 16, 8),
            ],
        ),
        Err(GenerationalGcError::DuplicateNurseryObjectLayout { address: young })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[NurseryObjectLayout::new(young, 0, 8)],
        ),
        Err(GenerationalGcError::InvalidNurseryObjectSize {
            address: young,
            size_bytes: 0,
        })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[NurseryObjectLayout::new(young, 8, 3)],
        ),
        Err(GenerationalGcError::InvalidNurseryObjectAlignment {
            address: young,
            align: 3,
        })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(young, 8, 8),
                NurseryObjectLayout::new(other, 16, 8),
            ],
        ),
        Err(GenerationalGcError::StaleNurseryObjectLayout { address: other })
    );

    let misaligned_destination = address(0x9008);
    let misaligned_relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(
            young,
            misaligned_destination,
        )],
    )
    .expect("misaligned relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &misaligned_relocation_plan,
            &[NurseryObjectLayout::new(young, 16, 16)],
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: young,
                generation: HeapGeneration::Young,
                destination: misaligned_destination,
                align: 16,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_rejects_overlapping_destination_ranges() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0x9008);
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

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(first, 16, 8),
                NurseryObjectLayout::new(second, 16, 8),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: first_destination,
                second_generation: HeapGeneration::Young,
                second: second_destination,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_rejects_cross_generation_destination_range_overlap() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0x9008);
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

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(copy, 16, 8),
                NurseryObjectLayout::new(promote, 16, 8),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: copy_destination,
                second_generation: HeapGeneration::Old,
                second: promote_destination,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_rejects_destination_source_range_overlap() {
    let young = address(0x1000);
    let destination = address(0x1008);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(young, destination)],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[NurseryObjectLayout::new(young, 16, 8)],
        ),
        Err(
            GenerationalGcError::MinorGcObjectCopyDestinationSourceRangeOverlap {
                source_address: young,
                destination,
            }
        )
    );
}

#[test]
fn minor_gc_forwarding_pointer_plan_maps_object_copies_to_forwarded_values() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 24, 8),
            NurseryObjectLayout::new(promote, 40, 16),
        ],
    )
    .expect("object-copy plan builds");

    let forwarding_plan = MinorGcForwardingPointerPlan::from_object_copy_plan(&copy_plan)
        .expect("forwarding plan builds");

    assert_eq!(forwarding_plan.len(), 2);
    assert!(!forwarding_plan.is_empty());
    assert_eq!(forwarding_plan.pointers()[0].copy(), copy_plan.copies()[0]);
    assert_eq!(forwarding_plan.pointers()[0].source(), copy);
    assert_eq!(
        forwarding_plan.pointers()[0].destination(),
        copy_destination
    );
    assert_eq!(
        forwarding_plan.pointers()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        forwarding_plan.pointers()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        forwarding_plan.pointers()[0].forwarded_value(),
        ResolvedValueGeneration::young(copy_destination)
    );
    assert_eq!(forwarding_plan.pointers()[1].source(), promote);
    assert_eq!(
        forwarding_plan.pointers()[1].destination(),
        promote_destination
    );
    assert_eq!(
        forwarding_plan.pointers()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        forwarding_plan.pointers()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        forwarding_plan.pointers()[1].forwarded_value(),
        ResolvedValueGeneration::old(promote_destination)
    );

    let empty_forwarding_plan =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&MinorGcObjectCopyPlan::default())
            .expect("empty forwarding plan builds");
    assert_eq!(empty_forwarding_plan.len(), 0);
    assert!(empty_forwarding_plan.is_empty());
}

#[test]
fn minor_gc_forwarding_pointer_plan_installs_into_forwarding_slots() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 24, 8),
            NurseryObjectLayout::new(promote, 40, 16),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_plan = MinorGcForwardingPointerPlan::from_object_copy_plan(&copy_plan)
        .expect("forwarding plan builds");
    let mut slots = [
        MinorGcForwardingSlot::new(copy),
        MinorGcForwardingSlot::new(promote),
    ];

    forwarding_plan
        .install_into_slots(&mut slots)
        .expect("forwarding slots install");

    assert_eq!(slots[0].source(), copy);
    assert_eq!(
        slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::young(copy_destination))
    );
    assert!(!slots[0].is_empty());
    assert_eq!(slots[1].source(), promote);
    assert_eq!(
        slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::old(promote_destination))
    );
    assert!(!slots[1].is_empty());
}

#[test]
fn minor_gc_forwarding_pointer_plan_rejects_stale_forwarding_slots() {
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
            NurseryObjectAge::new(second, 1),
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
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(first, 8, 8),
            NurseryObjectLayout::new(second, 16, 16),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_plan = MinorGcForwardingPointerPlan::from_object_copy_plan(&copy_plan)
        .expect("forwarding plan builds");

    let mut short_slots = [MinorGcForwardingSlot::new(first)];
    let unchanged_short_slots = short_slots;
    assert_eq!(
        forwarding_plan.install_into_slots(&mut short_slots),
        Err(
            GenerationalGcError::MinorGcForwardingPointerSlotLengthMismatch {
                pointers: 2,
                slots: 1,
            }
        )
    );
    assert_eq!(short_slots, unchanged_short_slots);

    let mut mismatched_slots = [
        MinorGcForwardingSlot::new(second),
        MinorGcForwardingSlot::new(first),
    ];
    let unchanged_mismatched_slots = mismatched_slots;
    assert_eq!(
        forwarding_plan.install_into_slots(&mut mismatched_slots),
        Err(
            GenerationalGcError::MinorGcForwardingPointerSlotSourceMismatch {
                index: 0,
                expected: first,
                actual: second,
            }
        )
    );
    assert_eq!(mismatched_slots, unchanged_mismatched_slots);

    let mut occupied_slots = [
        MinorGcForwardingSlot::new(first),
        MinorGcForwardingSlot::with_forwarded_value(
            second,
            ResolvedValueGeneration::young(first_destination),
        ),
    ];
    let unchanged_occupied_slots = occupied_slots;
    assert_eq!(
        forwarding_plan.install_into_slots(&mut occupied_slots),
        Err(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
            index: 1,
            address: second,
            actual: ResolvedValueGeneration::young(first_destination),
        })
    );
    assert_eq!(occupied_slots, unchanged_occupied_slots);
}

#[test]
fn minor_gc_reference_rewrite_plan_maps_young_slots_through_relocations() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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

    let rewrite_plan = MinorGcReferenceRewritePlan::from_references(
        &relocation_plan,
        [
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::old(address(0x3000)),
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::permanent(address(0x4000)),
            ResolvedValueGeneration::young(promote),
            ResolvedValueGeneration::young(copy),
        ],
    )
    .expect("rewrite plan builds");

    assert_eq!(rewrite_plan.len(), 3);
    assert!(!rewrite_plan.is_empty());
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 2);
    assert_eq!(rewrite_plan.rewrites()[0].source(), copy);
    assert_eq!(rewrite_plan.rewrites()[0].destination(), copy_destination);
    assert_eq!(
        rewrite_plan.rewrites()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        rewrite_plan.rewrites()[0].replacement(),
        ResolvedValueGeneration::young(copy_destination)
    );
    assert_eq!(rewrite_plan.rewrites()[1].slot(), 4);
    assert_eq!(rewrite_plan.rewrites()[1].source(), promote);
    assert_eq!(
        rewrite_plan.rewrites()[1].destination(),
        promote_destination
    );
    assert_eq!(
        rewrite_plan.rewrites()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        rewrite_plan.rewrites()[1].replacement(),
        ResolvedValueGeneration::old(promote_destination)
    );
    assert_eq!(rewrite_plan.rewrites()[2].slot(), 5);
    assert_eq!(rewrite_plan.rewrites()[2].source(), copy);
    assert_eq!(
        rewrite_plan.rewrites()[2].replacement(),
        ResolvedValueGeneration::young(copy_destination)
    );
}

#[test]
fn minor_gc_reference_rewrite_plan_applies_to_reference_slots() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
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
    let mut references = vec![
        ResolvedValueGeneration::Inline,
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::old(address(0x3000)),
        ResolvedValueGeneration::young(promote),
        ResolvedValueGeneration::young(copy),
    ];
    let rewrite_plan =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, references.clone())
            .expect("rewrite plan builds");

    rewrite_plan
        .apply_to_references(&mut references)
        .expect("rewrites apply");

    assert_eq!(
        references,
        [
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::young(copy_destination),
            ResolvedValueGeneration::old(address(0x3000)),
            ResolvedValueGeneration::old(promote_destination),
            ResolvedValueGeneration::young(copy_destination),
        ]
    );
}

#[test]
fn minor_gc_reference_rewrite_plan_rejects_stale_or_missing_slots() {
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
    let original_references = vec![
        ResolvedValueGeneration::young(first),
        ResolvedValueGeneration::young(second),
    ];
    let rewrite_plan = MinorGcReferenceRewritePlan::from_references(
        &relocation_plan,
        original_references.clone(),
    )
    .expect("rewrite plan builds");

    let mut stale_references = original_references.clone();
    stale_references[1] = ResolvedValueGeneration::Inline;
    assert_eq!(
        rewrite_plan.apply_to_references(&mut stale_references),
        Err(GenerationalGcError::MinorGcReferenceRewriteSlotMismatch {
            slot: 1,
            expected: second,
            actual: ResolvedValueGeneration::Inline,
        })
    );
    assert_eq!(
        stale_references,
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::Inline,
        ]
    );

    let mut short_references = vec![ResolvedValueGeneration::young(first)];
    assert_eq!(
        rewrite_plan.apply_to_references(&mut short_references),
        Err(GenerationalGcError::MinorGcReferenceRewriteSlotOutOfBounds { slot: 1, slots: 1 })
    );
    assert_eq!(short_references, [ResolvedValueGeneration::young(first)]);
}

#[test]
fn minor_gc_reference_rewrite_plan_rejects_unplanned_young_references() {
    let planned = address(0x1000);
    let missing = address(0x2000);
    let destination = address(0x9000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(planned)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(planned, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(planned, destination)],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcReferenceRewritePlan::from_references(
            &relocation_plan,
            [
                ResolvedValueGeneration::old(address(0x3000)),
                ResolvedValueGeneration::young(missing),
            ],
        ),
        Err(GenerationalGcError::MissingMinorGcReferenceRelocation { address: missing })
    );
    assert_eq!(
        MinorGcReferenceRewritePlan::from_references(
            &relocation_plan,
            [
                ResolvedValueGeneration::Inline,
                ResolvedValueGeneration::old(address(0x4000)),
                ResolvedValueGeneration::permanent(address(0x5000)),
            ],
        )
        .expect("non-young references need no rewrites")
        .rewrites(),
        &[]
    );
}

#[test]
fn minor_gc_remembered_set_refresh_rewrites_copied_edges_and_drops_old_targets() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let dead = address(0x3000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let first_source = address(0x4000);
    let promote_source = address(0x5000);
    let dead_source = address(0x6000);
    let second_source = address(0x7000);
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
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(13));
    remembered_set
        .record(RememberedEdge::new(first_source, copy))
        .expect("copy edge records");
    remembered_set
        .record(RememberedEdge::new(promote_source, promote))
        .expect("promote edge records");
    remembered_set
        .record(RememberedEdge::new(dead_source, dead))
        .expect("dead edge records");
    remembered_set
        .record(RememberedEdge::new(second_source, copy))
        .expect("second copy edge records");

    let refresh_plan = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("refresh plan builds");

    assert_eq!(refresh_plan.source_epoch(), RememberedSetEpoch::new(13));
    assert_eq!(refresh_plan.len(), 4);
    assert!(!refresh_plan.is_empty());
    assert_eq!(
        refresh_plan.refreshes()[0].original(),
        RememberedEdge::new(first_source, copy)
    );
    assert_eq!(
        refresh_plan.refreshes()[0].action(),
        MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
            refreshed: RememberedEdge::new(first_source, copy_destination),
        }
    );
    assert_eq!(
        refresh_plan.refreshes()[0].retained_edge(),
        Some(RememberedEdge::new(first_source, copy_destination))
    );
    assert_eq!(
        refresh_plan.refreshes()[1].action(),
        MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: promote_destination,
        }
    );
    assert_eq!(refresh_plan.refreshes()[1].retained_edge(), None);
    assert_eq!(
        refresh_plan.refreshes()[2].action(),
        MinorGcRememberedSetRefreshAction::DropDead
    );
    assert_eq!(refresh_plan.refreshes()[2].retained_edge(), None);
    assert_eq!(
        refresh_plan.refreshes()[3].action(),
        MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
            refreshed: RememberedEdge::new(second_source, copy_destination),
        }
    );
    assert_eq!(
        refresh_plan.retained_edges().collect::<Vec<_>>(),
        [
            RememberedEdge::new(first_source, copy_destination),
            RememberedEdge::new(second_source, copy_destination),
        ]
    );
    let rebuilt = refresh_plan
        .rebuild_remembered_set()
        .expect("remembered set rebuilds");
    assert_eq!(rebuilt.epoch(), RememberedSetEpoch::new(14));
    assert_eq!(
        rebuilt.edges(),
        &[
            RememberedEdge::new(first_source, copy_destination),
            RememberedEdge::new(second_source, copy_destination),
        ]
    );
}

#[test]
fn minor_gc_remembered_set_refresh_accepts_empty_snapshots() {
    let relocation_plan = MinorGcRelocationPlan::default();
    let remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(21));

    let refresh_plan = MinorGcRememberedSetRefreshPlan::from_snapshot(
        remembered_set.snapshot(),
        &relocation_plan,
    )
    .expect("empty refresh plan builds");

    assert_eq!(refresh_plan.source_epoch(), RememberedSetEpoch::new(21));
    assert!(refresh_plan.is_empty());
    assert_eq!(refresh_plan.refreshes(), &[]);
    assert_eq!(refresh_plan.retained_edges().collect::<Vec<_>>(), []);
    let rebuilt = refresh_plan
        .rebuild_remembered_set()
        .expect("empty remembered set rebuilds");
    assert_eq!(rebuilt.epoch(), RememberedSetEpoch::new(22));
    assert_eq!(rebuilt.edges(), &[]);

    let max_epoch_set = RememberedSet::with_epoch(RememberedSetEpoch::new(u64::MAX));
    let max_epoch_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
        max_epoch_set.snapshot(),
        &relocation_plan,
    )
    .expect("max epoch empty refresh plan builds");
    assert_eq!(
        max_epoch_refresh.rebuild_remembered_set(),
        Err(GenerationalGcError::RememberedSetEpochOverflow)
    );
}

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
    let forwarding_pointers =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)
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
        publication_commit_plan
            .publish_next_remembered_set(&mut changed_same_epoch_remembered_set),
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
    let unchanged_changed_same_length_remembered_set =
        changed_same_length_remembered_set.clone();
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
