use super::*;
use crate::heap::gc::{
    GcCardTable, MinorGcPromotionPolicy, MinorGcRelocationDestination,
    MinorGcRememberedSetRefreshPlan, MinorGcSurvivorAction, NurseryObjectAge, RememberedSet,
    RememberedSetEpoch,
};

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is aligned and non-null")
}

fn copied_and_promoted_relocation_plan() -> MinorGcRelocationPlan {
    let copied = address(0x1000);
    let promoted = address(0x2000);
    let plan = crate::heap::gc::MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copied),
            ResolvedValueGeneration::young(promoted),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copied, 0),
            NurseryObjectAge::new(promoted, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    assert_eq!(
        plan.survivors()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        plan.survivors()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );

    MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(copied, address(0x9000)),
            MinorGcRelocationDestination::new(promoted, address(0xa000)),
        ],
    )
    .expect("relocation plan builds")
}

#[test]
fn old_field_rescan_retains_copied_young_edges_and_drops_promoted_or_dead_targets() {
    let copied = address(0x1000);
    let promoted = address(0x2000);
    let dead = address(0x3000);
    let old_source = address(0x8000);
    let permanent_source = address(0x9000);
    let clean_source = address(0xa000);
    let relocation_plan = copied_and_promoted_relocation_plan();
    let mut cards = GcCardTable::new(0x1000).expect("card table builds");
    cards
        .mark_source(old_source)
        .expect("old source card is marked");
    cards
        .mark_source(permanent_source)
        .expect("permanent source card is marked");
    let old_source_fields = [
        ResolvedValueGeneration::young(copied),
        ResolvedValueGeneration::old(address(0x4000)),
        ResolvedValueGeneration::young(promoted),
        ResolvedValueGeneration::Inline,
        ResolvedValueGeneration::young(dead),
    ];
    let permanent_source_fields = [ResolvedValueGeneration::young(copied)];
    let clean_source_fields = [ResolvedValueGeneration::young(copied)];
    let young_source_fields = [ResolvedValueGeneration::young(copied)];
    let fields = [
        MinorGcOldObjectFields::new(old_source, HeapGeneration::Old, &old_source_fields),
        MinorGcOldObjectFields::new(
            permanent_source,
            HeapGeneration::Permanent,
            &permanent_source_fields,
        ),
        MinorGcOldObjectFields::new(clean_source, HeapGeneration::Old, &clean_source_fields),
        MinorGcOldObjectFields::new(address(0xb000), HeapGeneration::Young, &young_source_fields),
    ];

    let rescan =
        MinorGcOldFieldRescanPlan::from_dirty_cards(cards.snapshot(), &fields, &relocation_plan)
            .expect("old-field rescan builds");

    assert_eq!(rescan.len(), 4);
    assert!(!rescan.is_empty());
    assert_eq!(rescan.rescans()[0].source(), old_source);
    assert_eq!(rescan.rescans()[0].field_index(), 0);
    assert_eq!(
        rescan.rescans()[0].original(),
        RememberedEdge::new(old_source, copied)
    );
    assert_eq!(
        rescan.rescans()[0].action(),
        MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
            refreshed: RememberedEdge::new(old_source, address(0x9000)),
        }
    );
    assert_eq!(rescan.rescans()[1].field_index(), 2);
    assert_eq!(
        rescan.rescans()[1].original(),
        RememberedEdge::new(old_source, promoted)
    );
    assert_eq!(
        rescan.rescans()[1].action(),
        MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: address(0xa000),
        }
    );
    assert_eq!(rescan.rescans()[2].field_index(), 4);
    assert_eq!(
        rescan.rescans()[2].original(),
        RememberedEdge::new(old_source, dead)
    );
    assert_eq!(
        rescan.rescans()[2].action(),
        MinorGcRememberedSetRefreshAction::DropDead
    );
    assert_eq!(rescan.rescans()[3].source(), permanent_source);
    assert_eq!(
        rescan.retained_edges().collect::<Vec<_>>(),
        [
            RememberedEdge::new(old_source, address(0x9000)),
            RememberedEdge::new(permanent_source, address(0x9000)),
        ]
    );
}

#[test]
fn remembered_set_rebuild_merges_refresh_and_old_field_rescan_edges() {
    let copied = address(0x1000);
    let promoted = address(0x2000);
    let old_source = address(0x8000);
    let extra_source = address(0x9000);
    let relocation_plan = copied_and_promoted_relocation_plan();
    let mut remembered = RememberedSet::with_epoch(RememberedSetEpoch::new(7));
    remembered
        .record(RememberedEdge::new(old_source, copied))
        .expect("remembered copied edge records");
    remembered
        .record(RememberedEdge::new(old_source, promoted))
        .expect("remembered promoted edge records");
    let refresh =
        MinorGcRememberedSetRefreshPlan::from_snapshot(remembered.snapshot(), &relocation_plan)
            .expect("remembered-set refresh builds");
    let mut cards = GcCardTable::new(0x1000).expect("card table builds");
    cards
        .mark_source(old_source)
        .expect("duplicate source card marks");
    cards
        .mark_source(extra_source)
        .expect("extra source card marks");
    let old_source_fields = [ResolvedValueGeneration::young(copied)];
    let extra_source_fields = [ResolvedValueGeneration::young(copied)];
    let fields = [
        MinorGcOldObjectFields::new(old_source, HeapGeneration::Old, &old_source_fields),
        MinorGcOldObjectFields::new(extra_source, HeapGeneration::Old, &extra_source_fields),
    ];
    let rescan =
        MinorGcOldFieldRescanPlan::from_dirty_cards(cards.snapshot(), &fields, &relocation_plan)
            .expect("old-field rescan builds");

    let rebuilt = refresh
        .rebuild_remembered_set_with_old_field_rescan(&rescan)
        .expect("remembered set rebuilds with old-field rescan");

    assert_eq!(rebuilt.epoch(), RememberedSetEpoch::new(8));
    assert_eq!(
        rebuilt.edges(),
        &[
            RememberedEdge::new(old_source, address(0x9000)),
            RememberedEdge::new(extra_source, address(0x9000)),
        ]
    );
}

#[test]
fn old_field_rescan_accepts_empty_or_clean_inputs() {
    let copied = address(0x1000);
    let relocation_plan = copied_and_promoted_relocation_plan();
    let cards = GcCardTable::new(0x1000).expect("card table builds");
    let old_source_fields = [ResolvedValueGeneration::young(copied)];
    let fields = [MinorGcOldObjectFields::new(
        address(0x8000),
        HeapGeneration::Old,
        &old_source_fields,
    )];

    let rescan =
        MinorGcOldFieldRescanPlan::from_dirty_cards(cards.snapshot(), &fields, &relocation_plan)
            .expect("clean old-field rescan builds");

    assert!(rescan.is_empty());
    assert_eq!(rescan.rescans(), []);
    assert_eq!(rescan.retained_edges().collect::<Vec<_>>(), []);
}
