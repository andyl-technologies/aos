//! Typed logical failures retained by actual finite root-catalog decoding.
//!
//! Canonical fixtures are reconstructed from genuinely captured catalogs and
//! checked against their published identity before finite caller admission.
//! Exact-layout refusal targets only fallible logical vectors and strings;
//! these component controls grant no native authority or physical OOM proof.

use super::*;
use crate::content_envelope::{ContentChild, ContentEnvelope};
use crate::ram::codec::{ROOT_SCHEMA, SCHEMA_VERSION, decode_root_envelope};
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{RamError, RegionTreeDigest, RootRecord};
use std::alloc::Layout;
use std::collections::TryReserveError;

/// Reconstructs canonical catalog input from a genuinely captured root.
///
/// # Panics
/// Panics if capture, canonical identity or ordinary decoding fails.
pub(super) fn canonical_envelope(store: &RamStore) -> ContentEnvelope {
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &fixture_original(store),
            &mut || Ok(()),
        )
        .unwrap();
    let canonical = root.record().try_encode().unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    body.extend_from_slice(&canonical);
    let mut children = BTreeSet::new();
    for (index, reference) in root.regions.iter().enumerate() {
        body.extend_from_slice(reference.digest.as_bytes());
        body.extend_from_slice(&reference.height.to_be_bytes());
        body.extend_from_slice(&reference.pages.to_be_bytes());
        children.insert(ContentChild::new(format!("region-{index:08x}"), reference.id).unwrap());
    }
    let envelope = ContentEnvelope::new(ROOT_SCHEMA, SCHEMA_VERSION, children, body).unwrap();
    assert_eq!(
        ContentId::for_bytes(
            ObjectKind::ExactManifest,
            SCHEMA_VERSION,
            &envelope.canonical_bytes()
        ),
        root.object_id()
    );
    let (record, regions) = decode_root_envelope(&envelope).unwrap();
    assert_eq!(&record, root.record());
    assert_eq!(regions.as_slice(), root.regions.as_ref());
    envelope
}

fn root_refusal(layout: Layout) {
    let directory = tempfile::tempdir().unwrap();
    // This decode component explicitly reserves the existing maximum-width
    // caller bound; it changes neither ordinary fixtures nor production limits.
    let quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &quota);
    let envelope = canonical_envelope(&store);
    let baseline = quota.used();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original
        .charge_bytes(RootRecord::decoding_memory_bound(Limits::default()).unwrap())
        .unwrap();
    let admitted = quota.used();
    let requests = quota.reservations.load(Ordering::SeqCst);

    let (result, refused) =
        TestAllocationObserver::refuse_one_allocation(layout, || decode_root_envelope(&envelope))
            .unwrap();
    assert!(
        refused,
        "the actual fallible allocator refusal was not reached"
    );
    let error = result.unwrap_err();
    let cause = error
        .source()
        .and_then(|source| source.downcast_ref::<RamError>());
    assert!(
        cause.is_some(),
        "the actual logical cause was discarded: {error:?}"
    );
    assert!(cause.unwrap().source().unwrap().is::<TryReserveError>());
    assert_eq!(quota.reservations.load(Ordering::SeqCst), requests);
    assert_eq!(quota.used(), admitted);

    // The caller retains its original account through destruction of the
    // returned inline diagnostic; the error itself issues no new financial loan.
    drop(error);
    drop(original);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn root_inventory_allocator_refusal_retains_typed_logical_cause() {
    root_refusal(Layout::array::<RegionDescriptor>(1).unwrap());
}

#[test]
fn root_identifier_allocator_refusal_retains_typed_logical_cause() {
    root_refusal(Layout::array::<u8>(4).unwrap());
}

#[test]
fn root_selected_vector_allocator_refusal_retains_typed_logical_cause() {
    root_refusal(Layout::array::<RegionTreeDigest>(1).unwrap());
}

#[test]
fn actual_logical_validation_bridge_retains_cause_without_allocating() {
    let quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original
        .charge_bytes(RootRecord::decoding_memory_bound(Limits::default()).unwrap())
        .unwrap();
    let raw = RootRecord::decode(&[], Limits::default()).unwrap_err();
    assert_eq!(raw, RamError::Malformed);
    let requests = quota.reservations.load(Ordering::SeqCst);
    let admitted = quota.used();

    let (error, counts) = TestAllocationObserver::count(|| logical(raw));

    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<RamError>()),
        Some(&RamError::Malformed),
        "the actual validation cause was discarded: {error:?}"
    );
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(quota.reservations.load(Ordering::SeqCst), requests);
    assert_eq!(quota.used(), admitted);
    drop(error);
    drop(original);
    assert_eq!(quota.used(), 0);
}
