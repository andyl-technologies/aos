//! Retains real successor-vector allocator refusals under their caller account.
//!
//! Only the new fallible copies are injected. Each actual admission prefix is
//! observed before injection to rule out an earlier matching infallible extent.
//! Input construction precedes finite caller prepayment; these controls qualify
//! neither physical OOM nor native resource authority.

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

fn successor_vector_refusal(digests: bool) {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let retention = Retention::default();
    let regions = (0..REGION_COUNT)
        .map(|index| {
            RegionDescriptor::new(format!("ram.{index:02}"), RegionClass::MutableMain, 4096)
                .unwrap()
        })
        .collect();
    let topology = Topology::new(regions, Limits::default()).unwrap();
    let root = store
        .capture(
            topology,
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(root.regions.len(), REGION_COUNT);
    assert_eq!(root.record.region_roots().len(), REGION_COUNT);
    let backend_baseline = backend_quota.used();
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
            store.admit_ram_publication(root.record.topology(), root.record.scope())?;
            Ok::<(), RamStoreError>(())
        });
    prefix.unwrap();
    assert!(
        earlier.is_none(),
        "the target extent overlaps an earlier admission allocation"
    );
    assert_eq!(caller_quota.used(), admitted);
    let admission_requests = caller_quota.reservations.load(Ordering::SeqCst) - requests;
    let before_injection = caller_quota.reservations.load(Ordering::SeqCst);

    // Never inject the predecessor's infallible to_vec. Both new copies reserve
    // fallibly; their distinct extents separate the second from its first copy.
    let mut reads = 0;
    let mut callbacks = 0;
    let ((result, counts), refused) = TestAllocationObserver::refuse_one_allocation(layout, || {
        TestAllocationObserver::count(|| {
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
        })
    })
    .unwrap();
    assert!(refused, "the actual successor allocation was not refused");
    let error = result.unwrap_err();

    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::Allocation { .. })
    ));
    assert!(contains_allocator_refusal(&error));
    assert_eq!((reads, callbacks), (0, 0));
    assert!(!counts.overflow && !prefix_counts.overflow);
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (
            prefix_counts.allocations + u64::from(digests),
            prefix_counts.reallocations
        ),
        "refusal must add only an earlier successful catalog copy"
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
fn successor_catalog_vector_refusal_retains_original_allocator_cause() {
    successor_vector_refusal(false);
}

#[test]
fn successor_digest_vector_refusal_retains_original_allocator_cause() {
    successor_vector_refusal(true);
}
