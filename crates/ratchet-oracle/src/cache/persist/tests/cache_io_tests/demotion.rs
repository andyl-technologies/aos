//! Tests for the size-pressure demotion policy and victim selection.
//!
//! These cover the pure decision layer (doc 29 §5.4/§5.6/§5.7): the policy's
//! `demotion_bytes_to_free` overshoot math and `select_demotion_victims`'
//! largest-and-oldest ordering plus prefix selection. The two-location executor
//! integration test lives alongside them.

use super::*;

fn sample_key(byte: u8) -> PersistRootRecordKey {
    PersistRootRecordKey::from_digest([byte; 32])
}

fn candidate(key_byte: u8, resident_bytes: u64, mtime_unix_secs: u64) -> PersistDemotionCandidate {
    PersistDemotionCandidate::new(
        PersistRootRecordKey::from_digest([key_byte; 32]),
        resident_bytes,
        mtime_unix_secs,
    )
}

#[test]
fn demotion_disabled_by_default_frees_nothing() {
    let policy = PersistStorageMaintenancePolicy::default();
    assert_eq!(policy.primary_size_pressure_bytes(), None);
    assert_eq!(policy.demotion_bytes_to_free(1000), 0);
    assert_eq!(policy.demotion_bytes_to_free(0), 0);
}

#[test]
fn demotion_bytes_to_free_is_used_minus_bound() {
    let policy = PersistStorageMaintenancePolicy::default().with_primary_size_pressure_bytes(1000);
    assert_eq!(policy.primary_size_pressure_bytes(), Some(1000));
    // Within the bound frees nothing; over the bound frees the overshoot.
    assert_eq!(policy.demotion_bytes_to_free(600), 0);
    assert_eq!(policy.demotion_bytes_to_free(1000), 0);
    assert_eq!(policy.demotion_bytes_to_free(1500), 500);
}

#[test]
fn victims_are_ordered_largest_then_oldest() {
    let mut candidates = vec![
        candidate(1, 100, 5),
        candidate(2, 300, 9),
        candidate(3, 300, 2),
        candidate(4, 200, 1),
    ];
    // Free more than the total so every candidate is returned, exposing the
    // full order: 300-byte records first (older mtime wins the tie), then 200,
    // then 100.
    let victims = select_demotion_victims(&mut candidates, 10_000);
    let order: Vec<u8> = victims
        .iter()
        .map(|c| c.key().hash().as_bytes()[0])
        .collect();
    assert_eq!(order, vec![3, 2, 4, 1]);
}

#[test]
fn zero_target_selects_no_victims() {
    let mut candidates = vec![candidate(1, 100, 5), candidate(2, 300, 9)];
    let victims = select_demotion_victims(&mut candidates, 0);
    assert!(victims.is_empty());
}

#[test]
fn target_beyond_available_selects_all() {
    let mut candidates = vec![
        candidate(1, 100, 5),
        candidate(2, 300, 9),
        candidate(3, 200, 1),
    ];
    let victims = select_demotion_victims(&mut candidates, 10_000);
    assert_eq!(victims.len(), 3);
}

#[test]
fn minimal_prefix_relieves_the_target() {
    // 300 + 200 = 500 >= 450, so the two largest suffice; the 100-byte tail is
    // left resident.
    let mut candidates = vec![
        candidate(1, 100, 5),
        candidate(2, 300, 9),
        candidate(3, 200, 1),
    ];
    let victims = select_demotion_victims(&mut candidates, 450);
    let order: Vec<u8> = victims
        .iter()
        .map(|c| c.key().hash().as_bytes()[0])
        .collect();
    assert_eq!(order, vec![2, 3]);
}

/// A single-entry closure whose `.drv` payload is `filler` bytes of `fill`, so
/// distinct `fill` values never content-dedupe into one shared blob.
fn sized_closure(root: &str, fill: u8, filler: usize) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut closure = BTreeMap::new();
    closure.insert(PathBuf::from(root), vec![fill; filler]);
    closure
}

#[test]
fn demotion_moves_cold_victims_down_and_keeps_small_records_resident() {
    let primary_root = temp_root();
    let secondary_root = temp_root();
    let primary = PersistCache::open(&primary_root).expect("primary opens");
    let secondary = PersistCache::open(&secondary_root).expect("secondary opens");

    // Two large records (2 KiB closures, distinct payloads so they do not
    // dedupe) and two tiny ones. Store the large pair first so their files-pack
    // append offsets are the oldest — largest-and-oldest are the victims.
    let big_a = sized_closure("/nix/store/a.drv", b'a', 2000);
    let big_b = sized_closure("/nix/store/b.drv", b'b', 2000);
    let small_c = sized_closure("/nix/store/c.drv", b'c', 16);
    let small_d = sized_closure("/nix/store/d.drv", b'd', 16);
    primary
        .store_root_instantiation(sample_key(10), b"/nix/store/a.drv", &big_a, &[], 1)
        .expect("A stores");
    primary
        .store_root_instantiation(sample_key(11), b"/nix/store/b.drv", &big_b, &[], 2)
        .expect("B stores");
    primary
        .store_root_instantiation(sample_key(12), b"/nix/store/c.drv", &small_c, &[], 3)
        .expect("C stores");
    primary
        .store_root_instantiation(sample_key(13), b"/nix/store/d.drv", &small_d, &[], 4)
        .expect("D stores");

    // Bound the primary 3 KiB below its footprint: enough to demote the two
    // large records (~4 KiB together) but not the tiny tail.
    let used = primary
        .primary_used_bytes()
        .expect("primary footprint measures");
    let bound = used.saturating_sub(3000);
    let policy = PersistStorageMaintenancePolicy::default().with_primary_size_pressure_bytes(bound);

    let locations =
        PersistCacheLocations::with_primary(primary, vec![(PersistLatencyClass::Ssd, secondary)]);
    let outcome = locations
        .demote_under_size_pressure(policy)
        .expect("demotion runs");

    match &outcome {
        PersistDemotionOutcome::Demoted {
            demoted_keys,
            estimated_bytes_freed,
            target_class,
        } => {
            assert_eq!(*target_class, PersistLatencyClass::Ssd);
            assert!(
                *estimated_bytes_freed > 0,
                "moved records must report freed bytes"
            );
            let mut demoted = demoted_keys.clone();
            demoted.sort();
            let mut expected = vec![sample_key(10), sample_key(11)];
            expected.sort();
            assert_eq!(demoted, expected, "the two large records are the victims");
        }
        other => panic!("expected a Demoted outcome, got {other:?}"),
    }
    assert_eq!(outcome.demoted_count(), 2);

    // The victims are gone from the primary but live at the secondary; the
    // small records stay resident in the primary; and a multi-location probe
    // still finds every record (a demoted record answers from the secondary).
    let (_, secondary) = &locations.secondaries()[0];
    for victim in [sample_key(10), sample_key(11)] {
        assert!(
            locations
                .primary()
                .load_root_instantiation(victim)
                .expect("primary lookup succeeds")
                .is_none(),
            "a demoted record must be unrooted from the primary"
        );
        assert!(
            secondary
                .load_root_instantiation(victim)
                .expect("secondary lookup succeeds")
                .is_some(),
            "a demoted record must be readable at the secondary"
        );
    }
    for resident in [sample_key(12), sample_key(13)] {
        assert!(
            locations
                .primary()
                .load_root_instantiation(resident)
                .expect("primary lookup succeeds")
                .is_some(),
            "a small record must stay resident in the primary"
        );
    }
    for key in [
        sample_key(10),
        sample_key(11),
        sample_key(12),
        sample_key(13),
    ] {
        assert!(
            locations.load_root_instantiation(key).is_some(),
            "every record must remain findable across the location stack"
        );
    }

    let _ = fs::remove_dir_all(primary_root);
    let _ = fs::remove_dir_all(secondary_root);
}

#[test]
fn demotion_without_size_pressure_is_a_no_op() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    cache
        .store_root_instantiation(
            sample_key(20),
            b"/nix/store/x.drv",
            &sized_closure("/nix/store/x.drv", b'x', 64),
            &[],
            1,
        )
        .expect("record stores");

    // Default policy leaves demotion disabled; a bound above the footprint keeps
    // the primary within pressure. Both are no-ops with a secondary present.
    let secondary_root = temp_root();
    let secondary = PersistCache::open(&secondary_root).expect("secondary opens");
    let locations =
        PersistCacheLocations::with_primary(cache, vec![(PersistLatencyClass::Hdd, secondary)]);

    let disabled = locations
        .demote_under_size_pressure(PersistStorageMaintenancePolicy::default())
        .expect("disabled demotion runs");
    assert_eq!(
        disabled,
        PersistDemotionOutcome::Skipped {
            reason: PersistDemotionSkip::NoSizePressure
        }
    );

    let within = locations
        .demote_under_size_pressure(
            PersistStorageMaintenancePolicy::default().with_primary_size_pressure_bytes(1 << 30),
        )
        .expect("within-bound demotion runs");
    assert_eq!(
        within,
        PersistDemotionOutcome::Skipped {
            reason: PersistDemotionSkip::NoSizePressure
        }
    );

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(secondary_root);
}

#[test]
fn demotion_without_a_secondary_is_a_no_op() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    cache
        .store_root_instantiation(
            sample_key(30),
            b"/nix/store/y.drv",
            &sized_closure("/nix/store/y.drv", b'y', 2000),
            &[],
            1,
        )
        .expect("record stores");
    let used = cache.primary_used_bytes().expect("footprint measures");
    let policy = PersistStorageMaintenancePolicy::default()
        .with_primary_size_pressure_bytes(used.saturating_sub(1000));

    let locations = PersistCacheLocations::with_primary(cache, Vec::new());
    let outcome = locations
        .demote_under_size_pressure(policy)
        .expect("demotion runs");
    assert_eq!(
        outcome,
        PersistDemotionOutcome::Skipped {
            reason: PersistDemotionSkip::NoSecondaryLocation
        }
    );

    let _ = fs::remove_dir_all(root);
}
