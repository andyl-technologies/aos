//! Split-out PIC tests (part_1). See parent module.
use super::*;

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
