//! Actual page-proof allocation refusals under unchanged finite component credit.
//!
//! Exact-layout injection reaches fallible proof storage. It creates no physical
//! memory pressure, process envelope or native execution authority.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{EncodedPageProof, NodeDigest, PageDigest, PageProof};
use std::alloc::Layout;
use std::collections::TryReserveError;

fn actual_allocation_source<'a>(mut error: &'a (dyn Error + 'static)) -> &'a TryReserveError {
    loop {
        if let Some(source) = error.downcast_ref::<TryReserveError>() {
            return source;
        }
        error = error
            .source()
            .expect("the actual allocation cause is retained");
    }
}

fn reference_refusal(bytes: usize) -> TryReserveError {
    let (source, reached) = TestAllocationObserver::refuse_one_allocation(
        Layout::from_size_align(bytes, 1).unwrap(),
        || Vec::<u8>::new().try_reserve_exact(bytes).unwrap_err(),
    )
    .unwrap();
    assert!(reached);
    source
}

#[test]
fn fallible_page_proof_encoding_preserves_canonical_bytes_and_admitted_capacity() {
    for (region, depth) in [
        ("main".to_owned(), 0),
        ("main".to_owned(), 3),
        ("a".repeat(255), 52),
    ] {
        let digest = PageDigest::hash(&[7; 4096]).unwrap();
        let proof = PageProof::new(
            region,
            0,
            4096,
            digest,
            vec![crucible_ram::empty_leaf_digest(); depth],
        )
        .unwrap();
        let canonical = proof.encode();
        let capacity = 64 + proof.region_id().len() + depth * std::mem::size_of::<NodeDigest>();

        let encoded = proof.try_encode().unwrap();
        let owned = EncodedPageProof::try_new(proof.clone()).unwrap();

        assert_eq!(encoded, canonical);
        assert_eq!(encoded.capacity(), capacity);
        assert_eq!(owned.encoded(), canonical);
        assert_eq!(owned.encoding_capacity(), capacity);
        assert_eq!(owned.proof(), &proof);
        assert_eq!(
            PageProof::decode(&encoded, Limits::default()).unwrap(),
            proof
        );
    }
}

#[test]
fn page_encoding_allocator_refusal_retains_actual_prepaid_cause_without_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let baseline = quota.used();
    let object = page_object(&store);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let digest = PageDigest::hash(&[7; 4096]).unwrap();
    let page = store.read_page_object(object, digest, &mut work).unwrap();
    let proof = PageProof::new("main", 0, 4096, digest, Vec::new()).unwrap();
    let credit = crate::ram::page_read::proof_credit(&original, "main", 0).unwrap();
    let expected = reference_refusal(68);

    let ((error, counts), reached) = TestAllocationObserver::refuse_one_allocation(
        Layout::from_size_align(68, 1).unwrap(),
        || TestAllocationObserver::count(|| RamPageRead::try_new(page, proof, credit).unwrap_err()),
    )
    .unwrap();

    assert!(reached);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(actual_allocation_source(&error), &expected);
    let sticky = original.check().unwrap_err();
    assert_eq!(actual_allocation_source(&sticky), &expected);
    let (repeated, counts) = TestAllocationObserver::count(|| original.check().unwrap_err());
    assert_eq!(repeated, sticky);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    drop(repeated);
    drop(sticky);
    drop(work);
    drop(original);

    let retained = quota.used();
    assert!(retained > baseline);
    drop(error);
    assert_eq!(quota.used(), baseline);
}

fn lazy_path_allocation_refusal(bytes: usize) {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let root = store
        .capture(
            topology(8 * 4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let baseline = quota.used();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let expected = reference_refusal(bytes);

    let (error, reached) = TestAllocationObserver::refuse_one_allocation(
        Layout::from_size_align(bytes, 1).unwrap(),
        || {
            store
                .read_page_with_proof(&root, "main", 3, &original, &mut || Ok(()))
                .unwrap_err()
        },
    )
    .unwrap();

    assert!(reached);
    assert_eq!(actual_allocation_source(&error), &expected);
    let sticky = original.check().unwrap_err();
    assert_eq!(actual_allocation_source(&sticky), &expected);
    drop(sticky);
    let reservations = quota.reservations.load(Ordering::SeqCst);
    let repeated = store
        .read_page_with_proof(&root, "main", 3, &original, &mut || Ok(()))
        .unwrap_err();
    assert_eq!(actual_allocation_source(&repeated), &expected);
    assert_eq!(quota.reservations.load(Ordering::SeqCst), reservations);
    drop(repeated);
    drop(original);

    let retained = quota.used();
    assert!(retained > baseline);
    drop(error);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn lazy_page_sibling_allocator_refusal_is_actual_sticky_and_paid() {
    lazy_path_allocation_refusal(3 * std::mem::size_of::<NodeDigest>());
}

#[test]
fn lazy_page_region_allocator_refusal_is_actual_sticky_and_paid() {
    lazy_path_allocation_refusal(4);
}

#[test]
fn later_prepaid_allocation_refusal_preserves_the_original_first_cause() {
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let first = original.charge_bytes(METADATA_BYTES).unwrap_err();
    let later = reference_refusal(68);

    let (retained, counts) =
        TestAllocationObserver::count(|| original.retain_allocation_refusal(later));

    assert_eq!(retained, first);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    drop(original);
    let used = quota.used();
    assert!(used > 0);
    drop(first);
    assert_eq!(quota.used(), used);
    drop(retained);
    assert_eq!(quota.used(), 0);
}
