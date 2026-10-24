//! Capture output reservations refuse before staging or guest-byte reads.
//!
//! These controls inject only the new fallible paths. Their actual admission
//! prefix rules out an earlier infallible allocation with the same extent.
//! Caller funding remains finite and supplies no native resource authority.

use super::*;
use crate::ram::codec::TreeRef;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::RegionTreeDigest;
use std::alloc::Layout;
use std::collections::TryReserveError;

const REGION_COUNT: usize = 13;

fn contains_allocator_refusal(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(current) = source {
        if current.is::<TryReserveError>() {
            return true;
        }
        source = current.source();
    }
    false
}

fn capture_vector_refusal(digests: bool) {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let backend_baseline = backend_quota.used();
    let retention = Retention::default();
    let topology = Topology::new(
        (0..REGION_COUNT)
            .map(|index| {
                RegionDescriptor::new(format!("ram.{index:02}"), RegionClass::MutableMain, 4097)
                    .unwrap()
            })
            .collect(),
        Limits::default(),
    )
    .unwrap();
    let caller_quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = caller_quota.used();
    let requests = caller_quota.reservations.load(Ordering::SeqCst);
    let catalogs = Layout::array::<TreeRef>(REGION_COUNT).unwrap();
    let roots = Layout::array::<RegionTreeDigest>(REGION_COUNT).unwrap();
    assert_ne!(catalogs, roots);
    let layout = if digests { roots } else { catalogs };

    let (prefix, earlier, prefix_counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            let mut boundary = || Ok(());
            let _work = Work::new(store.limits, &original, &mut boundary)?;
            store.admit_ram_publication(&topology, Scope::Exact)?;
            original
                .verify_live()
                .map_err(|source| RamStoreError::from_admission(&original, source))
        });
    prefix.unwrap();
    assert!(
        earlier.is_none(),
        "the target extent overlaps an earlier admission allocation"
    );
    assert_eq!(caller_quota.used(), admitted);
    let admission_requests = caller_quota.reservations.load(Ordering::SeqCst) - requests;
    let before_injection = caller_quota.reservations.load(Ordering::SeqCst);

    // Never inject the predecessor's infallible Vec growth. Distinct exact
    // extents identify each new fallible output reservation before staging.
    let mut reads = 0;
    let mut callbacks = 0;
    let ((result, counts), refused) = TestAllocationObserver::refuse_one_allocation(layout, || {
        TestAllocationObserver::count(|| {
            store.capture(
                topology,
                Scope::Exact,
                &mut |region, index, bytes| {
                    reads += 1;
                    patterned(region, index, bytes)
                },
                &retention,
                &original,
                &mut || {
                    callbacks += 1;
                    Ok(())
                },
            )
        })
    })
    .unwrap();
    assert!(refused, "the actual output reservation was not refused");
    let error = result.unwrap_err();

    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::Allocation { .. })
    ));
    assert!(contains_allocator_refusal(&error));
    assert_eq!((reads, callbacks), (0, 0));
    assert!(retention.objects.lock().unwrap().is_empty());
    assert!(!counts.overflow && !prefix_counts.overflow);
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (
            prefix_counts.allocations + u64::from(digests),
            prefix_counts.reallocations
        ),
        "refusal must add only an earlier successful catalog reservation"
    );
    assert_eq!(
        caller_quota.reservations.load(Ordering::SeqCst),
        before_injection + admission_requests,
        "the returned diagnostic must request no additional loan"
    );
    assert_eq!(caller_quota.used(), admitted);
    assert_eq!(backend_quota.used(), backend_baseline);

    drop(original);
    assert_eq!(caller_quota.used(), admitted);
    drop(error);
    assert_eq!(caller_quota.used(), 0);
}

#[test]
fn capture_catalog_vector_refusal_retains_original_allocator_cause() {
    capture_vector_refusal(false);
}

#[test]
fn capture_digest_vector_refusal_retains_original_allocator_cause() {
    capture_vector_refusal(true);
}
