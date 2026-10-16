//! Exercises eviction decisions and physical-charge transitions independently.

use super::{CacheEntry, CachePolicy, CircuitBreaker, PolicyConfig};
use std::time::Duration;

fn cache() -> CachePolicy {
    CachePolicy::new(PolicyConfig {
        capacity: 100,
        low_watermark: 50,
        probation_bytes: 10,
        release_grace: Duration::from_secs(5),
        scan_limit: 32,
    })
    .unwrap()
}

fn insert(cache: &mut CachePolicy, key: &str, bytes: u64) {
    cache
        .reserve(key.to_owned(), "tenant".to_owned(), bytes)
        .unwrap();
    cache
        .admit(
            key,
            CacheEntry::new(key.to_owned(), bytes, "tenant".to_owned()),
        )
        .unwrap();
}

#[test]
fn host_cache_probation_main_second_chance_and_retirement_charge() {
    let mut cache = cache();
    insert(&mut cache, "hot", 30);
    insert(&mut cache, "cold", 30);
    insert(&mut cache, "warm", 30);
    cache.touch("hot");
    cache.touch("warm");

    let victims = cache.eviction_candidates(Duration::ZERO);

    assert_eq!(victims, ["cold", "hot"]);
    assert_eq!(cache.charged_bytes(), 90);
    assert!(cache.reserve("new".into(), "tenant".into(), 20).is_err());
    cache.finish_retirement("cold").unwrap();
    assert_eq!(cache.charged_bytes(), 60);
    cache.reserve("new".into(), "tenant".into(), 20).unwrap();
    assert_eq!(cache.charged_bytes(), 80);
}

#[test]
fn host_cache_pin_grace_and_read_cancellation_restore_queue_membership() {
    let mut cache = cache();
    insert(&mut cache, "pinned", 60);
    cache.pin("pinned").unwrap();
    assert!(
        cache
            .eviction_candidates(Duration::from_secs(20))
            .is_empty()
    );
    cache.release("pinned", Duration::from_secs(20)).unwrap();
    assert!(
        cache
            .eviction_candidates(Duration::from_secs(24))
            .is_empty()
    );
    assert_eq!(
        cache.eviction_candidates(Duration::from_secs(25)),
        ["pinned"]
    );

    cache.touch("pinned");

    assert!(cache.finish_retirement("pinned").is_err());
    assert_eq!(
        cache.eviction_candidates(Duration::from_secs(26)),
        ["pinned"]
    );
    cache.finish_retirement("pinned").unwrap();
    assert_eq!(cache.charged_bytes(), 0);
}

#[test]
fn host_cache_owner_quota_and_failed_reservation_are_exact() {
    let mut cache = cache();
    cache.set_quota("tenant".into(), 40);
    insert(&mut cache, "one", 30);
    assert!(
        cache
            .reserve("too-large".into(), "tenant".into(), 11)
            .is_err()
    );
    assert_eq!(cache.charged_bytes(), 30);
    cache.reserve("fits".into(), "tenant".into(), 10).unwrap();
    assert_eq!(cache.charged_bytes(), 40);
    cache.cancel_reservation("fits");
    assert_eq!(cache.charged_bytes(), 30);
}

#[test]
fn host_cache_circuit_probes_once_per_interval_and_recovers() {
    let mut circuit = CircuitBreaker::new(2, Duration::from_secs(3)).unwrap();
    circuit.failure(Duration::ZERO);
    assert!(circuit.allow(Duration::ZERO));
    circuit.failure(Duration::ZERO);
    assert!(!circuit.allow(Duration::from_secs(2)));
    assert!(circuit.allow(Duration::from_secs(3)));
    assert!(!circuit.allow(Duration::from_secs(3)));
    circuit.success();
    assert!(circuit.allow(Duration::from_secs(3)));
}

#[test]
fn host_cache_eviction_counts_reservations_and_large_incoming_allocations() {
    let mut cache = cache();
    insert(&mut cache, "resident", 40);
    cache
        .reserve("inflight".into(), "other-owner".into(), 50)
        .unwrap();

    assert_eq!(
        cache.eviction_candidates_for(50, Duration::ZERO),
        ["resident"]
    );
    assert_eq!(cache.charged_bytes(), 90);
    cache.finish_retirement("resident").unwrap();
    assert_eq!(cache.charged_bytes(), 50);
    cache
        .reserve("incoming".into(), "tenant".into(), 50)
        .unwrap();
    assert_eq!(cache.charged_bytes(), 100);
}
