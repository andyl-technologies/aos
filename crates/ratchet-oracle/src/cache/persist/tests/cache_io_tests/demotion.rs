//! Tests for the size-pressure demotion policy and victim selection.
//!
//! These cover the pure decision layer (doc 29 §5.4/§5.6/§5.7): the policy's
//! `demotion_bytes_to_free` overshoot math and `select_demotion_victims`'
//! largest-and-oldest ordering plus prefix selection. The two-location executor
//! integration test lives alongside them.

use super::*;

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
    let mut candidates = vec![candidate(1, 100, 5), candidate(2, 300, 9), candidate(3, 200, 1)];
    let victims = select_demotion_victims(&mut candidates, 10_000);
    assert_eq!(victims.len(), 3);
}

#[test]
fn minimal_prefix_relieves_the_target() {
    // 300 + 200 = 500 >= 450, so the two largest suffice; the 100-byte tail is
    // left resident.
    let mut candidates = vec![candidate(1, 100, 5), candidate(2, 300, 9), candidate(3, 200, 1)];
    let victims = select_demotion_victims(&mut candidates, 450);
    let order: Vec<u8> = victims
        .iter()
        .map(|c| c.key().hash().as_bytes()[0])
        .collect();
    assert_eq!(order, vec![2, 3]);
}
