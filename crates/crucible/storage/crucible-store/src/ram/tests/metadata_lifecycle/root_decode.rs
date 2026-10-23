//! Actual root-catalog allocation costs under finite original caller admission.
//!
//! Canonical input matches a genuinely captured root. The caller prepays the
//! complete storage decode bound, including returned catalog references. These
//! component controls issue no kernel quota or native execution authority.

use super::*;
use super::logical_causes::canonical_envelope;
use crate::content_envelope::ContentEnvelope;
use crate::ram::codec::{TreeRef, decode_root_envelope};
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{RamError, RootRecord};
use std::alloc::Layout;
use std::collections::TryReserveError;

fn canonical_record(envelope: &ContentEnvelope) -> &[u8] {
    let body = envelope.body();
    let length = u32::from_be_bytes(body[..4].try_into().unwrap());
    let length = usize::try_from(length).unwrap();
    &body[4..4 + length]
}

fn caller_account(quota: &Arc<ObservedQuota>) -> DecodeBudget {
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    // The storage bound also covers the returned reference vector; the
    // portable record's own bound covers only the logical decoding prefix.
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    original
}

#[test]
fn root_catalog_decode_allocates_only_its_returned_reference_vector() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &quota);
    let envelope = canonical_envelope(&store);
    let baseline = quota.used();
    let original = caller_account(&quota);
    let requests = quota.reservations.load(Ordering::SeqCst);
    let admitted = quota.used();

    let (logical, prefix_counts) = TestAllocationObserver::count(|| {
        RootRecord::decode(canonical_record(&envelope), Limits::default()).unwrap()
    });
    let digest = logical.digest();
    drop(logical);

    let ((record, references), counts) =
        TestAllocationObserver::count(|| decode_root_envelope(&envelope).unwrap());

    assert_eq!(record.digest(), digest);
    assert_eq!(references.len(), 1);
    assert!(!prefix_counts.overflow && !counts.overflow);
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (prefix_counts.allocations + 1, prefix_counts.reallocations),
        "catalog decoding must add only its returned reference vector"
    );
    assert_eq!(quota.reservations.load(Ordering::SeqCst), requests);
    assert_eq!(quota.used(), admitted);
    drop(record);
    drop(references);
    drop(original);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn root_catalog_reference_vector_refusal_preserves_typed_cause() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &quota);
    let envelope = canonical_envelope(&store);
    let baseline = quota.used();
    let original = caller_account(&quota);
    let layout = Layout::array::<TreeRef>(1).unwrap();
    let requests = quota.reservations.load(Ordering::SeqCst);
    let admitted = quota.used();

    // Refuse only the new fallible vector. An earlier infallible inventory
    // control with the same layout must stop this test before injection.
    let (logical, earlier, prefix_counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            RootRecord::decode(canonical_record(&envelope), Limits::default()).unwrap()
        });
    assert!(
        earlier.is_none(),
        "the vector layout overlaps an earlier allocation"
    );
    drop(logical);

    // The predecessor's infallible reference-vector allocation is never injected.
    let ((result, counts), refused) = TestAllocationObserver::refuse_one_allocation(layout, || {
        TestAllocationObserver::count(|| decode_root_envelope(&envelope))
    })
    .unwrap();
    assert!(
        refused,
        "the actual reference-vector refusal was not reached"
    );
    let error = result.unwrap_err();

    assert!(matches!(
        &error,
        RamStoreError::LogicalValidation(RamError::Allocation(_))
    ));
    assert!(
        error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .is::<TryReserveError>()
    );
    assert!(!prefix_counts.overflow && !counts.overflow);
    assert_eq!(counts.allocations, prefix_counts.allocations);
    assert_eq!(counts.reallocations, prefix_counts.reallocations);
    assert_eq!(quota.reservations.load(Ordering::SeqCst), requests);
    assert_eq!(quota.used(), admitted);
    drop(error);
    drop(original);
    assert_eq!(quota.used(), baseline);
}
