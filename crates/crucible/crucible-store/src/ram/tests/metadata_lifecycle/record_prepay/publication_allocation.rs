//! Actual staging allocation refusals before any durable publication effect.
//!
//! Exact-layout injection uses the existing finite component bank. It neither
//! induces physical OOM nor establishes native process resource authority.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use std::alloc::Layout;
use std::collections::TryReserveError;

fn actual_source<'a>(mut error: &'a (dyn Error + 'static)) -> &'a TryReserveError {
    loop {
        if let Some(source) = error.downcast_ref::<TryReserveError>() {
            return source;
        }
        error = error
            .source()
            .expect("the actual allocator source is retained");
    }
}

#[test]
fn publication_batch_allocator_refusal_is_sticky_without_replacement_diagnostic_storage() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let baseline = quota.used();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let layout = Layout::array::<crate::ram::PendingPublication>(64).unwrap();
    // The real pending array is pointer aligned. The reference allocator error
    // must carry that same layout, independently of its element type.
    let (expected, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        Vec::<crate::ram::PendingPublication>::new()
            .try_reserve_exact(64)
            .unwrap_err()
    })
    .unwrap();
    assert!(reached);

    let ((error, counts), reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        TestAllocationObserver::count(|| store.begin_publication_batch(&mut work).unwrap_err())
    })
    .unwrap();

    assert!(reached);
    assert_eq!(actual_source(&error), &expected);
    assert!(work.pending.is_none());
    // The real scratch receipt is born before the attempted array. Only that
    // pre-admitted receipt may allocate; reporting the refusal adds no storage.
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let sticky = original.check().unwrap_err();
    assert_eq!(actual_source(&sticky), &expected);
    drop(sticky);
    let reservations = quota.reservations.load(Ordering::SeqCst);
    let (repeated, counts) =
        TestAllocationObserver::count(|| store.begin_publication_batch(&mut work).unwrap_err());
    assert_eq!(actual_source(&repeated), &expected);
    assert_eq!(quota.reservations.load(Ordering::SeqCst), reservations);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    drop(repeated);
    drop(work);
    drop(original);

    assert!(quota.used() > baseline);
    drop(error);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn publication_input_vector_allocator_refusal_prevents_backend_effects_and_releases_staging() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let baseline = quota.used();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    store.begin_publication_batch(&mut work).unwrap();
    let (id, _) = store
        .put_page(&[9; 4096], &OriginalRetention, &mut work)
        .unwrap();
    assert_eq!(work.pending.as_ref().unwrap().len(), 1);
    assert!(!store.backend.contains(id).unwrap());
    let layout = Layout::array::<(ContentId, BlobHandle)>(1).unwrap();
    assert_ne!(
        layout,
        Layout::array::<Option<(ContentId, u64)>>(1).unwrap()
    );
    let (expected, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        Vec::<(ContentId, BlobHandle)>::new()
            .try_reserve_exact(1)
            .unwrap_err()
    })
    .unwrap();
    assert!(reached);

    let (error, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        store.flush_publication_batch(&mut work).unwrap_err()
    })
    .unwrap();

    assert!(reached);
    assert_eq!(actual_source(&error), &expected);
    assert!(work.pending.is_none());
    assert!(!store.backend.contains(id).unwrap());
    let sticky = original.check().unwrap_err();
    assert_eq!(actual_source(&sticky), &expected);
    drop(sticky);
    let reservations = quota.reservations.load(Ordering::SeqCst);
    store.begin_publication_batch(&mut work).unwrap_err();
    assert_eq!(quota.reservations.load(Ordering::SeqCst), reservations);
    drop(work);
    drop(original);

    assert!(quota.used() > baseline);
    drop(error);
    assert_eq!(quota.used(), baseline);
}
