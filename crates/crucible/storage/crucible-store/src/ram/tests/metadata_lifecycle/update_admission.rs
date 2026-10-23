//! Refuses revoked update originals before constructing successor metadata.
//!
//! A genuinely captured root has an independently live backend. Its finite
//! caller prepays the existing output bound, then revokes that same authority.
//! The actual admission-refusal prefix distinguishes diagnostic allocations
//! from copies of successor vectors; no native resources are qualified.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;

fn contains_original_revocation(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(current) = source {
        if current.is::<RevokedOriginalAuthority>() {
            return true;
        }
        source = current.source();
    }
    false
}

#[test]
fn revoked_update_original_refuses_before_successor_vector_copies() {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let retention = Retention::default();
    let root = store
        .capture(
            topology(8193),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let backend_baseline = backend_quota.used();
    let caller_quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = caller_quota.used();
    let requests = caller_quota.reservations.load(Ordering::SeqCst);
    caller_quota.revoked.store(true, Ordering::SeqCst);

    // Compare the real same-account refusal, including its typed diagnostic,
    // rather than assuming that operational refusal itself allocates nothing.
    let (prefix_error, prefix_counts) = TestAllocationObserver::count(|| {
        Work::new(store.limits, &original, &mut || Ok(()))
            .err()
            .unwrap()
    });
    assert!(contains_original_revocation(&prefix_error));
    assert_eq!(caller_quota.used(), admitted);
    drop(prefix_error);

    let mut reads = 0;
    let mut callbacks = 0;
    let (result, counts) = TestAllocationObserver::count(|| {
        store.update_with_reader(
            &root,
            &mut || {
                reads += 1;
                Ok(None)
            },
            &retention,
            &original,
            &mut || {
                callbacks += 1;
                Ok(())
            },
        )
    });
    let error = result.unwrap_err();

    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!((reads, callbacks), (0, 0));
    assert!(!counts.overflow && !prefix_counts.overflow);
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (prefix_counts.allocations, prefix_counts.reallocations),
        "successor vectors must not precede original admission"
    );
    assert_eq!(caller_quota.reservations.load(Ordering::SeqCst), requests);
    assert_eq!(caller_quota.used(), admitted);
    assert_eq!(backend_quota.used(), backend_baseline);
    assert!(!backend_quota.revoked.load(Ordering::SeqCst));

    drop(error);
    drop(original);
    assert_eq!(caller_quota.used(), 0);
}
