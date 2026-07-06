//! Unit tests for polymorphic attr selection inline caches.

use super::super::shape::{ShapeTable, ShapedAttrs};
use super::super::{AttrEntry, FlatAttrs};
use super::*;
use crate::attrs::hamt::HamtAttrs;
use crate::syntax::SymbolTable;
use crate::value::Value;

fn entry(shape: u32, slot: u32) -> InlineCacheEntry {
    InlineCacheEntry::new(InlineCacheShapeId::new(shape), slot)
}

fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<crate::syntax::Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for name in names {
        ids.push(table.intern(name).expect("symbol interns"));
    }
    (table, ids)
}

fn shaped_attrs(
    shape_table: &mut ShapeTable,
    symbols: &SymbolTable,
    keys: &[crate::syntax::Symbol],
    values: &[Value],
) -> ShapedAttrs {
    let shape = shape_table
        .intern_construction_order(keys, symbols)
        .expect("shape interns");
    ShapedAttrs::from_source_order(shape, values).expect("shaped attrs build")
}

fn flat_attrs(
    symbols: &SymbolTable,
    keys: &[crate::syntax::Symbol],
    values: &[Value],
) -> FlatAttrs {
    let entries = keys
        .iter()
        .copied()
        .zip(values.iter().copied())
        .map(|(key, value)| AttrEntry::new(key, value))
        .collect::<Vec<_>>();
    FlatAttrs::new(entries, symbols).expect("flat attrs build")
}

fn expect_flat_hit_int(
    outcome: FlatSelectOutcome,
    expected_value: i64,
    expected_slot: u32,
) -> FlatSelectSource {
    let FlatSelectOutcome::Hit {
        value,
        slot,
        source,
    } = outcome
    else {
        panic!("expected flat select hit");
    };
    assert_eq!(value.as_int().expect("int value"), expected_value);
    assert_eq!(slot, expected_slot);
    source
}

fn expect_hit_int(
    outcome: ShapedSelectOutcome,
    expected_value: i64,
    expected_slot: u32,
) -> ShapedSelectSource {
    let ShapedSelectOutcome::Hit {
        value,
        slot,
        source,
    } = outcome
    else {
        panic!("expected shaped select hit");
    };
    assert_eq!(value.as_int().expect("int value"), expected_value);
    assert_eq!(slot, expected_slot);
    source
}

fn expect_hamt_hit_int(outcome: HamtSelectOutcome, expected_value: i64) -> HamtSelectSource {
    let HamtSelectOutcome::Hit { value, source } = outcome else {
        panic!("expected HAMT select hit");
    };
    assert_eq!(value.as_int().expect("int value"), expected_value);
    source
}

fn expect_hamt_missing(outcome: HamtSelectOutcome) -> HamtSelectSource {
    let HamtSelectOutcome::Missing { source } = outcome else {
        panic!("expected HAMT select missing");
    };
    source
}

#[test]
fn flat_select_cache_installs_then_uses_cached_slot() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let attrs = flat_attrs(
        &symbols,
        &[ids[1], ids[0]],
        &[Value::int(20), Value::int(10)],
    );
    let mut cache = FlatSelectCache::new();

    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&attrs, ids[0])
                .expect("flat select resolves through slow path"),
            10,
            0,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(cache.state().entry_count(), 1);

    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&attrs, ids[0])
                .expect("flat select uses cached slot"),
            10,
            0,
        ),
        FlatSelectSource::Cached
    );
}

#[test]
fn flat_select_cache_widens_across_key_validated_slots() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
    let key = ids[1];
    let first = flat_attrs(&symbols, &[key], &[Value::int(1)]);
    let second = flat_attrs(&symbols, &[ids[0], key], &[Value::int(10), Value::int(2)]);
    let third = flat_attrs(
        &symbols,
        &[ids[0], key, ids[2]],
        &[Value::int(10), Value::int(3), Value::int(30)],
    );
    let mut cache = FlatSelectCache::new();

    assert_eq!(
        expect_flat_hit_int(cache.select(&first, key).expect("first flat select"), 1, 0,),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_flat_hit_int(
            cache.select(&second, key).expect("second flat select"),
            2,
            1,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
        }
    );
    assert_eq!(cache.state().entry_count(), 2);
    assert_eq!(
        expect_flat_hit_int(cache.select(&third, key).expect("third flat select"), 3, 1,),
        FlatSelectSource::Cached
    );
}

#[test]
fn flat_select_cache_revalidates_stale_slot_keys_before_loading() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let first = flat_attrs(&symbols, &[key], &[Value::int(1)]);
    let shifted = flat_attrs(&symbols, &[ids[0], key], &[Value::int(999), Value::int(2)]);
    let mut cache = FlatSelectCache::new();

    assert_eq!(
        expect_flat_hit_int(cache.select(&first, key).expect("first flat select"), 1, 0,),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&shifted, key)
                .expect("stale cached slot falls back to slow path"),
            2,
            1,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
        }
    );
}

#[test]
fn flat_select_cache_can_go_megamorphic_after_slot_cap() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let first = flat_attrs(&symbols, &[key], &[Value::int(1)]);
    let second = flat_attrs(&symbols, &[ids[0], key], &[Value::int(10), Value::int(2)]);
    let third = flat_attrs(&symbols, &[key], &[Value::int(3)]);
    let mut cache = FlatSelectCache::with_cap(1).expect("nonzero cap");

    assert_eq!(
        expect_flat_hit_int(cache.select(&first, key).expect("first flat select"), 1, 0,),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_flat_hit_int(
            cache.select(&second, key).expect("second flat select"),
            2,
            1,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::BecameMegamorphic,
        }
    );
    assert!(cache.state().is_megamorphic());
    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&third, key)
                .expect("megamorphic flat select stays on slow path"),
            3,
            0,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::AlreadyMegamorphic,
        }
    );
}

#[test]
fn flat_select_cache_missing_key_does_not_update_cache() {
    let (symbols, ids) = symbols(&[b"a", b"missing"]);
    let attrs = flat_attrs(&symbols, &[ids[0]], &[Value::int(1)]);
    let mut cache = FlatSelectCache::new();

    assert!(matches!(
        cache
            .select(&attrs, ids[1])
            .expect("missing flat key is not an error"),
        FlatSelectOutcome::Missing
    ));
    assert_eq!(cache.state().entry_count(), 0);
}

#[test]
fn flat_select_cache_specialized_missing_key_keeps_cached_slots() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let present = flat_attrs(&symbols, &[ids[0], key], &[Value::int(10), Value::int(20)]);
    let missing = flat_attrs(&symbols, &[ids[0]], &[Value::int(10)]);
    let mut cache = FlatSelectCache::new();

    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&present, key)
                .expect("first flat select resolves"),
            20,
            1,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(cache.state().entry_count(), 1);

    assert!(matches!(
        cache
            .select(&missing, key)
            .expect("missing key does not update specialized flat cache"),
        FlatSelectOutcome::Missing
    ));
    assert_eq!(cache.state().entry_count(), 1);

    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&present, key)
                .expect("cached flat slot remains usable"),
            20,
            1,
        ),
        FlatSelectSource::Cached
    );
}

#[test]
fn flat_select_cache_polymorphic_missing_key_keeps_cached_slots() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let first = flat_attrs(&symbols, &[key], &[Value::int(1)]);
    let second = flat_attrs(&symbols, &[ids[0], key], &[Value::int(10), Value::int(2)]);
    let missing = flat_attrs(&symbols, &[ids[0]], &[Value::int(10)]);
    let mut cache = FlatSelectCache::new();

    assert_eq!(
        expect_flat_hit_int(cache.select(&first, key).expect("first flat select"), 1, 0),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_flat_hit_int(
            cache.select(&second, key).expect("second flat select"),
            2,
            1,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
        }
    );
    assert_eq!(cache.state().entry_count(), 2);

    assert!(matches!(
        cache
            .select(&missing, key)
            .expect("missing key does not update polymorphic flat cache"),
        FlatSelectOutcome::Missing
    ));
    assert_eq!(cache.state().entry_count(), 2);

    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&first, key)
                .expect("first flat slot remains cached"),
            1,
            0,
        ),
        FlatSelectSource::Cached
    );
    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&second, key)
                .expect("second flat slot remains cached"),
            2,
            1,
        ),
        FlatSelectSource::Cached
    );
}

#[test]
fn flat_select_cache_megamorphic_missing_key_stays_megamorphic() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let first = flat_attrs(&symbols, &[key], &[Value::int(1)]);
    let second = flat_attrs(&symbols, &[ids[0], key], &[Value::int(10), Value::int(2)]);
    let missing = flat_attrs(&symbols, &[ids[0]], &[Value::int(10)]);
    let mut cache = FlatSelectCache::with_cap(1).expect("nonzero cap");

    assert_eq!(
        expect_flat_hit_int(cache.select(&first, key).expect("first flat select"), 1, 0),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_flat_hit_int(
            cache.select(&second, key).expect("second flat select"),
            2,
            1,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::BecameMegamorphic,
        }
    );
    assert!(cache.state().is_megamorphic());

    assert!(matches!(
        cache
            .select(&missing, key)
            .expect("missing key keeps megamorphic flat cache"),
        FlatSelectOutcome::Missing
    ));
    assert!(cache.state().is_megamorphic());

    assert_eq!(
        expect_flat_hit_int(
            cache
                .select(&first, key)
                .expect("megamorphic flat cache uses slow path"),
            1,
            0,
        ),
        FlatSelectSource::Resolved {
            update: InlineCacheUpdate::AlreadyMegamorphic,
        }
    );
}

#[test]
fn flat_select_cache_rejects_key_changes() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let attrs = flat_attrs(
        &symbols,
        &[ids[0], ids[1]],
        &[Value::int(10), Value::int(20)],
    );
    let mut cache = FlatSelectCache::new();

    cache
        .select(&attrs, ids[0])
        .expect("first flat select binds key");
    assert_eq!(
        cache
            .select(&attrs, ids[1])
            .expect_err("same flat select site cannot change keys"),
        FlatSelectError::KeyChanged {
            previous: ids[0],
            attempted: ids[1],
        }
    );
}

#[test]
fn hamt_select_cache_installs_distinguished_entry_then_reuses_it() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let attrs = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(10)),
            AttrEntry::new(ids[1], Value::int(20)),
        ],
        &symbols,
    )
    .expect("HAMT attrs build");
    let mut cache = HamtSelectCache::new(HamtSelectPolicy::DistinguishedEntry);

    assert_eq!(
        expect_hamt_hit_int(
            cache
                .select(&attrs, ids[1])
                .expect("HAMT select resolves policy"),
            20,
        ),
        HamtSelectSource::Resolved {
            update: HamtSelectUpdate::InstalledDistinguishedHamt,
        }
    );
    assert_eq!(cache.state(), HamtSelectCacheState::DistinguishedHamt);

    assert_eq!(
        expect_hamt_hit_int(
            cache
                .select(&attrs, ids[1])
                .expect("HAMT select reuses policy"),
            20,
        ),
        HamtSelectSource::CachedDistinguishedHamt
    );
}

#[test]
fn hamt_select_cache_records_distinguished_entry_for_missing_keys() {
    let (symbols, ids) = symbols(&[b"a", b"missing"]);
    let attrs = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(10))], &symbols)
        .expect("HAMT attrs build");
    let mut cache = HamtSelectCache::new(HamtSelectPolicy::DistinguishedEntry);

    assert_eq!(
        expect_hamt_missing(
            cache
                .select(&attrs, ids[1])
                .expect("HAMT missing select resolves policy"),
        ),
        HamtSelectSource::Resolved {
            update: HamtSelectUpdate::InstalledDistinguishedHamt,
        }
    );
    assert_eq!(
        expect_hamt_missing(
            cache
                .select(&attrs, ids[1])
                .expect("HAMT missing select reuses policy"),
        ),
        HamtSelectSource::CachedDistinguishedHamt
    );
}

#[test]
fn hamt_select_cache_rechecks_distinguished_missing_keys_on_new_hamt_values() {
    let (symbols, ids) = symbols(&[b"a", b"missing"]);
    let missing = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(10))], &symbols)
        .expect("missing HAMT attrs build");
    let present = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(10)),
            AttrEntry::new(ids[1], Value::int(20)),
        ],
        &symbols,
    )
    .expect("present HAMT attrs build");
    let mut cache = HamtSelectCache::new(HamtSelectPolicy::DistinguishedEntry);

    assert_eq!(
        expect_hamt_missing(
            cache
                .select(&missing, ids[1])
                .expect("missing HAMT select resolves policy"),
        ),
        HamtSelectSource::Resolved {
            update: HamtSelectUpdate::InstalledDistinguishedHamt,
        }
    );
    assert_eq!(cache.state(), HamtSelectCacheState::DistinguishedHamt);

    assert_eq!(
        expect_hamt_hit_int(
            cache
                .select(&present, ids[1])
                .expect("present HAMT select still performs keyed lookup"),
            20,
        ),
        HamtSelectSource::CachedDistinguishedHamt
    );
}

#[test]
fn hamt_select_cache_can_fold_hamt_values_into_megamorphic_path() {
    let (symbols, ids) = symbols(&[b"a"]);
    let attrs = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(10))], &symbols)
        .expect("HAMT attrs build");
    let mut cache = HamtSelectCache::new(HamtSelectPolicy::MegamorphicFallback);

    assert_eq!(
        expect_hamt_hit_int(
            cache
                .select(&attrs, ids[0])
                .expect("HAMT select becomes megamorphic"),
            10,
        ),
        HamtSelectSource::Resolved {
            update: HamtSelectUpdate::BecameMegamorphic,
        }
    );
    assert!(cache.state().is_megamorphic());
    assert_eq!(
        expect_hamt_hit_int(
            cache
                .select(&attrs, ids[0])
                .expect("HAMT select remains megamorphic"),
            10,
        ),
        HamtSelectSource::Resolved {
            update: HamtSelectUpdate::AlreadyMegamorphic,
        }
    );
}

#[test]
fn hamt_select_cache_rejects_key_changes() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let attrs = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(10)),
            AttrEntry::new(ids[1], Value::int(20)),
        ],
        &symbols,
    )
    .expect("HAMT attrs build");
    let mut cache = HamtSelectCache::new(HamtSelectPolicy::DistinguishedEntry);

    cache
        .select(&attrs, ids[0])
        .expect("first HAMT select binds key");
    assert_eq!(
        cache
            .select(&attrs, ids[1])
            .expect_err("same select site cannot change keys"),
        HamtSelectError::KeyChanged {
            previous: ids[0],
            attempted: ids[1],
        }
    );
}

#[test]
fn shaped_select_cache_installs_then_uses_cached_slot() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let attrs = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[1], ids[0]],
        &[Value::int(20), Value::int(10)],
    );
    let mut cache = ShapedSelectCache::new();

    assert_eq!(
        expect_hit_int(
            cache
                .select(&attrs, ids[0])
                .expect("select resolves through slow path"),
            10,
            0,
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(cache.state().entry_count(), 1);

    assert_eq!(
        expect_hit_int(
            cache
                .select(&attrs, ids[0])
                .expect("select uses cached slot"),
            10,
            0,
        ),
        ShapedSelectSource::Cached
    );
}

#[test]
fn shaped_select_cache_widens_then_goes_megamorphic() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let first = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(1)]);
    let second = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[1], ids[0]],
        &[Value::int(20), Value::int(2)],
    );
    let third = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[2], ids[0]],
        &[Value::int(30), Value::int(3)],
    );
    let mut cache = ShapedSelectCache::with_cap(2).expect("nonzero cap");

    assert_eq!(
        expect_hit_int(cache.select(&first, ids[0]).expect("first select"), 1, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_hit_int(cache.select(&second, ids[0]).expect("second select"), 2, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
        }
    );
    assert_eq!(cache.state().entry_count(), 2);
    assert_eq!(
        expect_hit_int(cache.select(&third, ids[0]).expect("third select"), 3, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::BecameMegamorphic,
        }
    );
    assert!(cache.state().is_megamorphic());
    assert_eq!(
        expect_hit_int(cache.select(&first, ids[0]).expect("mega select"), 1, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::AlreadyMegamorphic,
        }
    );
}

#[test]
fn shaped_select_cache_missing_key_does_not_update_cache() {
    let (symbols, ids) = symbols(&[b"a", b"missing"]);
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let attrs = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(1)]);
    let mut cache = ShapedSelectCache::new();

    assert!(matches!(
        cache
            .select(&attrs, ids[1])
            .expect("missing key is not an error"),
        ShapedSelectOutcome::Missing
    ));
    assert_eq!(cache.state().entry_count(), 0);
}

#[test]
fn shaped_select_cache_specialized_missing_key_keeps_cached_entries() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let present = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[0], key],
        &[Value::int(10), Value::int(20)],
    );
    let missing = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(10)]);
    let mut cache = ShapedSelectCache::new();

    assert_eq!(
        expect_hit_int(
            cache
                .select(&present, key)
                .expect("first shaped select resolves"),
            20,
            1,
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(cache.state().entry_count(), 1);

    assert!(matches!(
        cache
            .select(&missing, key)
            .expect("missing key does not update specialized shaped cache"),
        ShapedSelectOutcome::Missing
    ));
    assert_eq!(cache.state().entry_count(), 1);

    assert_eq!(
        expect_hit_int(
            cache
                .select(&present, key)
                .expect("cached shaped slot remains usable"),
            20,
            1,
        ),
        ShapedSelectSource::Cached
    );
}

#[test]
fn shaped_select_cache_polymorphic_missing_key_keeps_cached_entries() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let first = shaped_attrs(&mut shape_table, &symbols, &[key], &[Value::int(1)]);
    let second = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[0], key],
        &[Value::int(10), Value::int(2)],
    );
    let missing = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(10)]);
    let mut cache = ShapedSelectCache::new();

    assert_eq!(
        expect_hit_int(
            cache.select(&first, key).expect("first shaped select"),
            1,
            0
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_hit_int(
            cache.select(&second, key).expect("second shaped select"),
            2,
            1,
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
        }
    );
    assert_eq!(cache.state().entry_count(), 2);

    assert!(matches!(
        cache
            .select(&missing, key)
            .expect("missing key does not update polymorphic shaped cache"),
        ShapedSelectOutcome::Missing
    ));
    assert_eq!(cache.state().entry_count(), 2);

    assert_eq!(
        expect_hit_int(
            cache
                .select(&first, key)
                .expect("first shaped entry remains cached"),
            1,
            0,
        ),
        ShapedSelectSource::Cached
    );
    assert_eq!(
        expect_hit_int(
            cache
                .select(&second, key)
                .expect("second shaped entry remains cached"),
            2,
            1,
        ),
        ShapedSelectSource::Cached
    );
}

#[test]
fn shaped_select_cache_megamorphic_missing_key_stays_megamorphic() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let key = ids[1];
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let first = shaped_attrs(&mut shape_table, &symbols, &[key], &[Value::int(1)]);
    let second = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[0], key],
        &[Value::int(10), Value::int(2)],
    );
    let missing = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(10)]);
    let mut cache = ShapedSelectCache::with_cap(1).expect("nonzero cap");

    assert_eq!(
        expect_hit_int(
            cache.select(&first, key).expect("first shaped select"),
            1,
            0
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_hit_int(
            cache.select(&second, key).expect("second shaped select"),
            2,
            1,
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::BecameMegamorphic,
        }
    );
    assert!(cache.state().is_megamorphic());

    assert!(matches!(
        cache
            .select(&missing, key)
            .expect("missing key keeps megamorphic shaped cache"),
        ShapedSelectOutcome::Missing
    ));
    assert!(cache.state().is_megamorphic());

    assert_eq!(
        expect_hit_int(
            cache
                .select(&first, key)
                .expect("megamorphic shaped cache uses slow path"),
            1,
            0,
        ),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::AlreadyMegamorphic,
        }
    );
}

#[test]
fn shaped_select_cache_rejects_same_shape_with_different_slot() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let attrs = shaped_attrs(
        &mut shape_table,
        &symbols,
        &[ids[0], ids[1]],
        &[Value::int(1), Value::int(2)],
    );
    let mut cache = ShapedSelectCache::new();

    assert_eq!(
        expect_hit_int(cache.select(&attrs, ids[0]).expect("first select"), 1, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        cache
            .select(&attrs, ids[1])
            .expect_err("same select site cannot change slots for one shape"),
        ShapedSelectError::KeyChanged {
            previous: ids[0],
            attempted: ids[1],
        }
    );
}

#[test]
fn shaped_select_cache_does_not_cross_hit_foreign_same_id_shapes() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut left_table = ShapeTable::new().expect("left shape table initializes");
    let mut right_table = ShapeTable::new().expect("right shape table initializes");
    let left = shaped_attrs(&mut left_table, &symbols, &[ids[0]], &[Value::int(1)]);
    let right = shaped_attrs(&mut right_table, &symbols, &[ids[0]], &[Value::int(2)]);
    assert_eq!(left.shape().id(), right.shape().id());
    assert!(!left.shape().ptr_eq(right.shape()));
    let mut cache = ShapedSelectCache::new();

    assert_eq!(
        expect_hit_int(cache.select(&left, ids[0]).expect("left select"), 1, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::InstalledMonomorphic,
        }
    );
    assert_eq!(
        expect_hit_int(cache.select(&right, ids[0]).expect("right select"), 2, 0),
        ShapedSelectSource::Resolved {
            update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
        }
    );
}

#[test]
fn default_cache_starts_uninitialized_with_cap_four() {
    let cache = InlineCache::new();

    assert_eq!(cache.cap(), DEFAULT_POLYMORPHIC_CAP);
    assert_eq!(cache.state(), &InlineCacheState::Uninitialized);
    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), None);
}

#[test]
fn first_resolution_installs_monomorphic_entry() {
    let mut cache = InlineCache::new();

    assert_eq!(
        cache.record_resolution(entry(1, 7)),
        Ok(InlineCacheUpdate::InstalledMonomorphic)
    );

    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(7));
    assert_eq!(cache.state().entry_count(), 1);
}

#[test]
fn second_distinct_shape_widens_to_polymorphic() {
    let mut cache = InlineCache::new();
    cache
        .record_resolution(entry(1, 7))
        .expect("first resolution installs");

    assert_eq!(
        cache.record_resolution(entry(2, 11)),
        Ok(InlineCacheUpdate::WidenedToPolymorphic { len: 2 })
    );

    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(7));
    assert_eq!(cache.lookup(InlineCacheShapeId::new(2)), Some(11));
    assert_eq!(cache.state().entry_count(), 2);
}

#[test]
fn polymorphic_cache_adds_until_cap_then_goes_megamorphic() {
    let mut cache = InlineCache::with_cap(3).expect("nonzero cap");
    cache
        .record_resolution(entry(1, 10))
        .expect("first resolution installs");
    cache
        .record_resolution(entry(2, 20))
        .expect("second resolution widens");

    assert_eq!(
        cache.record_resolution(entry(3, 30)),
        Ok(InlineCacheUpdate::AddedPolymorphic { len: 3 })
    );
    assert_eq!(cache.lookup(InlineCacheShapeId::new(3)), Some(30));

    assert_eq!(
        cache.record_resolution(entry(4, 40)),
        Ok(InlineCacheUpdate::BecameMegamorphic)
    );
    assert!(cache.state().is_megamorphic());
    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), None);
    assert_eq!(
        cache.record_resolution(entry(5, 50)),
        Ok(InlineCacheUpdate::AlreadyMegamorphic)
    );
}

#[test]
fn cap_one_goes_megamorphic_on_second_shape() {
    let mut cache = InlineCache::with_cap(1).expect("nonzero cap");
    cache
        .record_resolution(entry(1, 10))
        .expect("first resolution installs");

    assert_eq!(
        cache.record_resolution(entry(2, 20)),
        Ok(InlineCacheUpdate::BecameMegamorphic)
    );
    assert!(cache.state().is_megamorphic());
}

#[test]
fn repeated_shape_reuses_existing_entry_without_duplication() {
    let mut cache = InlineCache::new();
    cache
        .record_resolution(entry(1, 10))
        .expect("first resolution installs");

    assert_eq!(
        cache.record_resolution(entry(1, 10)),
        Ok(InlineCacheUpdate::ReusedExisting)
    );
    assert_eq!(cache.state().entry_count(), 1);
}

#[test]
fn repeated_polymorphic_shape_reuses_existing_entry_without_duplication() {
    let mut cache = InlineCache::new();
    cache
        .record_resolution(entry(1, 10))
        .expect("first resolution installs");
    cache
        .record_resolution(entry(2, 20))
        .expect("second resolution widens");

    assert_eq!(
        cache.record_resolution(entry(2, 20)),
        Ok(InlineCacheUpdate::ReusedExisting)
    );
    assert_eq!(cache.state().entry_count(), 2);
    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(10));
    assert_eq!(cache.lookup(InlineCacheShapeId::new(2)), Some(20));
}

#[test]
fn same_shape_with_different_slot_is_rejected() {
    let mut cache = InlineCache::new();
    cache
        .record_resolution(entry(1, 10))
        .expect("first resolution installs");

    assert_eq!(
        cache.record_resolution(entry(1, 11)),
        Err(InlineCacheError::ShapeSlotChanged {
            shape: InlineCacheShapeId::new(1),
            previous_slot: 10,
            attempted_slot: 11,
        })
    );
    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(10));
}

#[test]
fn polymorphic_same_shape_with_different_slot_is_rejected() {
    let mut cache = InlineCache::new();
    cache
        .record_resolution(entry(1, 10))
        .expect("first resolution installs");
    cache
        .record_resolution(entry(2, 20))
        .expect("second resolution widens");

    assert_eq!(
        cache.record_resolution(entry(2, 21)),
        Err(InlineCacheError::ShapeSlotChanged {
            shape: InlineCacheShapeId::new(2),
            previous_slot: 20,
            attempted_slot: 21,
        })
    );
    assert_eq!(cache.state().entry_count(), 2);
    assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(10));
    assert_eq!(cache.lookup(InlineCacheShapeId::new(2)), Some(20));
}

#[test]
fn zero_custom_cap_is_rejected() {
    assert_eq!(
        InlineCache::with_cap(0),
        Err(InlineCacheError::ZeroPolymorphicCap)
    );
}
