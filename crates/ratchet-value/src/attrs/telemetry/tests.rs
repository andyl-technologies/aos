//! Unit tests for attr telemetry snapshots and counters.

use super::*;
use crate::attrs::hamt::HamtAttrs;
use crate::attrs::pic::{
    FlatSelectCache, HamtSelectCache, HamtSelectPolicy, InlineCache, InlineCacheEntry,
    InlineCacheShapeId, ShapedSelectCache,
};
use crate::attrs::repr::AttrSetReprPolicy;
use crate::attrs::select::{AttrSelectOutcome, AttrSelectSource, AttrSelectTarget, select_slow};
use crate::attrs::shape::{ShapeTable, ShapedAttrs};
use crate::attrs::{AttrEntry, FlatAttrs};
use crate::syntax::SymbolTable;
use crate::value::Value;

fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<crate::syntax::Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for name in names {
        ids.push(table.intern(name).expect("symbol interns"));
    }
    (table, ids)
}

#[test]
fn shape_census_counts_distinct_shapes_and_multiplicity() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let empty = table.empty();
    let one = table
        .intern_construction_order(&[ids[1]], &symbols)
        .expect("shape interns");
    let two = table
        .intern_construction_order(&[ids[1], ids[0]], &symbols)
        .expect("shape interns");
    let mut telemetry = AttrTelemetry::new();

    telemetry
        .record_shape_instance(&empty)
        .expect("empty shape records");
    telemetry
        .record_shape_instance(&one)
        .expect("one shape records");
    telemetry
        .record_shape_instance(&one)
        .expect("one shape records again");
    telemetry
        .record_shape_instance(&two)
        .expect("two shape records");
    telemetry
        .record_shape_instance(&two)
        .expect("two shape records again");

    let snapshot = telemetry.shape_census().expect("snapshot builds");
    assert_eq!(snapshot.total_instances, 5);
    assert_eq!(snapshot.distinct_shapes, 3);
    assert_eq!(
        snapshot
            .shapes
            .iter()
            .map(|entry| (entry.id.as_u32(), entry.key_count, entry.instances))
            .collect::<Vec<_>>(),
        vec![(0, 0, 1), (1, 1, 2), (2, 2, 2)]
    );
    assert_eq!(
        snapshot.multiplicity.as_ref(),
        &[
            ShapeMultiplicityBucket {
                instances_per_shape: 1,
                shape_count: 1,
            },
            ShapeMultiplicityBucket {
                instances_per_shape: 2,
                shape_count: 2,
            },
        ]
    );
}

#[test]
fn inline_cache_histogram_separates_sites_from_lookup_outcomes() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let shape = table
        .intern_construction_order(&[ids[0]], &symbols)
        .expect("shape interns");
    let attrs = ShapedAttrs::from_source_order(shape, &[Value::int(7)]).expect("attrs builds");
    let flat_attrs = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(7))], &symbols)
        .expect("flat attrs build");
    let mut shaped_cache = ShapedSelectCache::new();
    let mut flat_cache = FlatSelectCache::new();
    flat_cache
        .select(&flat_attrs, ids[0])
        .expect("flat select resolves");
    let resolved = shaped_cache
        .select(&attrs, ids[0])
        .expect("first select resolves");
    let cached = shaped_cache
        .select(&attrs, ids[0])
        .expect("second select hits cache");
    let missing = shaped_cache
        .select(&attrs, ids[1])
        .expect_err("same cache rejects changed key");
    let mut shaped_missing_cache = ShapedSelectCache::new();
    let shaped_missing = shaped_missing_cache
        .select(&attrs, ids[1])
        .expect("missing shaped select resolves");

    let mut generic_cache = InlineCache::with_cap(1).expect("cap is valid");
    generic_cache
        .record_resolution(InlineCacheEntry::new(InlineCacheShapeId::new(1), 0))
        .expect("first resolution installs");
    generic_cache
        .record_resolution(InlineCacheEntry::new(InlineCacheShapeId::new(2), 0))
        .expect("second resolution makes megamorphic");

    let mut telemetry = AttrTelemetry::new();
    telemetry
        .record_inline_cache_site(generic_cache.state())
        .expect("generic IC site records");
    telemetry
        .record_flat_select_site(flat_cache.state())
        .expect("flat select site records");
    telemetry
        .record_shaped_select_site(shaped_cache.state())
        .expect("shaped select site records");
    telemetry
        .record_shaped_select_lookup(shaped_cache.state(), &resolved)
        .expect("resolved shaped lookup records");
    telemetry
        .record_shaped_select_lookup(shaped_cache.state(), &cached)
        .expect("cached shaped lookup records");
    telemetry
        .record_shaped_select_lookup(shaped_missing_cache.state(), &shaped_missing)
        .expect("missing shaped lookup records");
    assert!(matches!(
        missing,
        super::super::pic::ShapedSelectError::KeyChanged { .. }
    ));

    let snapshot = telemetry.inline_cache_snapshot();
    assert_eq!(snapshot.generic_sites.megamorphic, 1);
    assert_eq!(snapshot.flat_select_sites.monomorphic, 1);
    assert_eq!(snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
}

#[test]
fn hamt_select_lookup_histogram_tracks_cached_and_resolved_paths() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let attrs = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("HAMT attrs build");
    let mut cache = HamtSelectCache::new(HamtSelectPolicy::DistinguishedEntry);
    let resolved = cache.select(&attrs, ids[0]).expect("select resolves");
    let cached_hit = cache.select(&attrs, ids[0]).expect("select hits");
    let cached_missing = cache.select(&attrs, ids[1]).expect_err("key changes");
    let mut fallback = HamtSelectCache::new(HamtSelectPolicy::MegamorphicFallback);
    let resolved_missing = fallback
        .select(&attrs, ids[1])
        .expect("missing select resolves fallback");

    let mut telemetry = AttrTelemetry::new();
    telemetry
        .record_hamt_select_site(cache.state())
        .expect("distinguished HAMT site records");
    telemetry
        .record_hamt_select_site(fallback.state())
        .expect("fallback HAMT site records");
    telemetry
        .record_hamt_select_lookup(&resolved)
        .expect("resolved HAMT lookup records");
    telemetry
        .record_hamt_select_lookup(&cached_hit)
        .expect("cached HAMT lookup records");
    telemetry
        .record_hamt_select_lookup(&resolved_missing)
        .expect("resolved missing HAMT lookup records");
    assert!(matches!(
        cached_missing,
        super::super::pic::HamtSelectError::KeyChanged { .. }
    ));

    let snapshot = telemetry.inline_cache_snapshot();
    assert_eq!(snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(snapshot.hamt_select_sites.megamorphic, 1);
    assert_eq!(snapshot.hamt_select_lookups.hits, 2);
    assert_eq!(snapshot.hamt_select_lookups.misses, 1);
    assert_eq!(snapshot.hamt_select_lookups.cached_hits, 1);
    assert_eq!(snapshot.hamt_select_lookups.resolved_hits, 1);
    assert_eq!(snapshot.hamt_select_lookups.resolved_misses, 1);
}

#[test]
fn slow_select_histogram_tracks_representation_hits_and_misses() {
    let (symbols, ids) = symbols(&[b"a", b"missing"]);
    let flat = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("flat attrs build");
    let hamt = HamtAttrs::from_flat(&flat, &symbols).expect("HAMT attrs build");
    let mut table = ShapeTable::new().expect("shape table initializes");
    let shape = table
        .intern_construction_order(&[ids[0]], &symbols)
        .expect("shape interns");
    let shaped =
        ShapedAttrs::from_source_order(shape, &[Value::int(1)]).expect("shaped attrs build");
    let mut telemetry = AttrTelemetry::new();

    for outcome in [
        select_slow(AttrSelectTarget::Flat(&flat), ids[0]).expect("flat hit records"),
        select_slow(AttrSelectTarget::Flat(&flat), ids[1]).expect("flat miss records"),
        select_slow(AttrSelectTarget::Hamt(&hamt), ids[0]).expect("HAMT hit records"),
        select_slow(AttrSelectTarget::Hamt(&hamt), ids[1]).expect("HAMT miss records"),
        select_slow(AttrSelectTarget::Shaped(&shaped), ids[0]).expect("shaped hit records"),
        select_slow(AttrSelectTarget::Shaped(&shaped), ids[1]).expect("shaped miss records"),
    ] {
        telemetry
            .record_slow_select_lookup(&outcome)
            .expect("slow-select outcome records");
    }

    assert_eq!(
        telemetry.slow_select_snapshot(),
        SlowSelectLookupCounts {
            flat_hits: 1,
            flat_misses: 1,
            hamt_hits: 1,
            hamt_misses: 1,
            shaped_hits: 1,
            shaped_misses: 1,
        }
    );
}

#[test]
fn slow_select_histogram_reports_counter_overflow() {
    let mut counts = SlowSelectLookupCounts {
        flat_hits: usize::MAX,
        ..SlowSelectLookupCounts::default()
    };

    assert_eq!(
        counts.record(&AttrSelectOutcome::Hit {
            value: Value::int(1),
            source: AttrSelectSource::Flat,
        }),
        Err(AttrTelemetryError::CounterOverflow {
            counter: "flat slow-select hits",
        })
    );
}

#[test]
fn update_merge_histograms_record_sizes_depths_reasons_and_hamt_summaries() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
    let left = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("left attrs build");
    let right = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(2)),
            AttrEntry::new(ids[2], Value::int(3)),
        ],
        &symbols,
    )
    .expect("right attrs build");
    let policy = AttrSetReprPolicy::new(1, 4).expect("thresholds are valid");
    let merge = super::super::repr::AttrSetReprValue::from_flat(left)
        .update_from_flat_right(&right, policy, 2, &symbols)
        .expect("merge dispatch succeeds");
    let mut telemetry = AttrTelemetry::new();

    telemetry
        .record_repr_decision(
            AttrSetConstruction::StaticLiteral { len: 10 },
            AttrSetReprDecision::Flat {
                result_len_upper_bound: 10,
                reason: AttrSetReprReason::StaticLiteral,
            },
        )
        .expect("static decision records");
    telemetry
        .record_update_merge(1, 2, 2, merge.decision(), merge.hamt_summary())
        .expect("merge records");

    let snapshot = telemetry
        .update_merge_snapshot()
        .expect("update snapshot builds");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.hamt_decisions, 1);
    assert_eq!(snapshot.update_merges, 1);
    assert_eq!(snapshot.hamt_update_merges, 1);
    assert_eq!(snapshot.hamt_inserted, 1);
    assert_eq!(snapshot.hamt_replaced, 1);
    assert_eq!(snapshot.reasons.static_literal, 1);
    assert_eq!(snapshot.reasons.large_update_merge, 1);
    assert_eq!(snapshot.left_len_distribution.as_ref(), &[bucket(1, 1)]);
    assert_eq!(snapshot.right_len_distribution.as_ref(), &[bucket(2, 1)]);
    assert_eq!(
        snapshot.result_len_upper_bound_distribution.as_ref(),
        &[bucket(3, 1)]
    );
    assert_eq!(
        snapshot.override_chain_depth_distribution.as_ref(),
        &[bucket(2, 1)]
    );
}

#[test]
fn flat_update_decisions_reject_hamt_summary_without_mutating_snapshot() {
    let flat = AttrSetReprDecision::Flat {
        result_len_upper_bound: 2,
        reason: AttrSetReprReason::SmallShapeStable,
    };
    let mut telemetry = AttrTelemetry::new();

    assert_eq!(
        telemetry.record_update_merge(1, 1, 1, flat, Some(HamtMergeSummary::default())),
        Err(AttrTelemetryError::UnexpectedHamtSummaryForFlatDecision)
    );

    let snapshot = telemetry
        .update_merge_snapshot()
        .expect("empty snapshot builds");
    assert_eq!(snapshot.decisions, 0);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.flat_update_merges, 0);
    assert_eq!(snapshot.hamt_inserted, 0);
    assert_eq!(snapshot.hamt_replaced, 0);
}

#[test]
fn order_parity_stats_count_matches_and_mismatches() {
    let mut telemetry = AttrTelemetry::new();

    telemetry
        .record_order_parity_check(true)
        .expect("match records");
    telemetry
        .record_order_parity_check(false)
        .expect("mismatch records");
    telemetry
        .record_order_parity_check(true)
        .expect("second match records");

    assert_eq!(
        telemetry.order_parity_stats(),
        OrderParityStats {
            matched: 2,
            mismatched: 1,
        }
    );
}

fn bucket(value: usize, count: usize) -> HistogramBucket {
    HistogramBucket { value, count }
}
