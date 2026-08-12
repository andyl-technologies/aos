//! Shared Candidate-C scalar-store concurrency and domain tests.

use std::sync::Arc;

use super::*;

fn test_reservation() -> Arc<ReservedArena> {
    Arc::new(ReservedArena::with_capacity(1 << 20).expect("test reservation maps"))
}

#[test]
fn shared_scalar_store_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SharedCandidateCScalarStore>();
}

#[test]
fn workers_share_hash_consed_scalar_words() {
    let store = Arc::new(SharedCandidateCScalarStore::new(test_reservation(), 32));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        workers.push(std::thread::spawn(move || {
            let int = store.encode_int(i64::MAX).expect("wide integer encodes");
            let float = store.encode_float(-0.0).expect("float encodes");
            (int, float)
        }));
    }

    let mut words = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker completes"));
    let first = words.next().expect("at least one worker");
    assert!(words.all(|words| words == first));
    assert_eq!(store.len(), 2);
    assert_eq!(store.payload_bytes(), 16);
    assert_eq!(
        store.decode_int(first.0).expect("integer decodes"),
        i64::MAX
    );
    assert_eq!(
        store
            .decode_float(first.1)
            .expect("float decodes")
            .to_bits(),
        (-0.0f64).to_bits()
    );
}

#[test]
fn shared_scalar_store_rejects_another_reservation_domain() {
    let left = SharedCandidateCScalarStore::new(test_reservation(), 16);
    let right = SharedCandidateCScalarStore::new(test_reservation(), 16);
    let word = left.encode_int(i64::MIN).expect("wide integer encodes");

    assert!(matches!(
        right.decode_int(word),
        Err(CandidateCScalarError::ArenaDomainMismatch { .. })
    ));
}

#[test]
fn shared_scalar_store_rejects_another_typed_registry_in_same_domain() {
    let arena = test_reservation();
    let left = SharedCandidateCScalarStore::new(Arc::clone(&arena), 16);
    let right = SharedCandidateCScalarStore::new(arena, 16);
    let word = left.encode_float(42.5).expect("float encodes");

    assert!(matches!(
        right.decode_float(word),
        Err(CandidateCScalarError::ScalarCellNotFound { .. })
    ));
}
