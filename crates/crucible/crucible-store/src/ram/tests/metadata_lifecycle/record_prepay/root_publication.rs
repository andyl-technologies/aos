//! Actual root publication allocations under finite original component credit.
//!
//! Controls preserve canonical manifests, original callbacks and actual allocator
//! sources. They establish no kernel quota, native custody or physical OOM.

use super::*;
use crate::content_envelope::ContentChild;
use crate::ram::codec::{ROOT_SCHEMA, SCHEMA_VERSION, TreeRef};
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{RegionTreeDigest, RootRecord};
use std::alloc::Layout;
use std::collections::{BTreeSet, TryReserveError};

fn captured_root(store: &RamStore) -> LeasedRamRoot {
    store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &fixture_original(store),
            &mut || Ok(()),
        )
        .unwrap()
}

#[derive(Clone, Copy)]
enum RootAllocation {
    Logical,
    Body,
    Schema,
    Role,
}

fn allocator_source<'a>(mut error: &'a (dyn Error + 'static)) -> &'a TryReserveError {
    loop {
        if let Some(source) = error.downcast_ref::<TryReserveError>() {
            return source;
        }
        error = error
            .source()
            .expect("the actual allocator source is retained");
    }
}

fn refusal_at(allocation: RootAllocation) {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let root = captured_root(&store);
    let baseline = quota.used();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let retention = Retention::default();
    let bytes = match allocation {
        RootAllocation::Logical => root.record().encoded_len(),
        RootAllocation::Body => 4 + root.record().encoded_len() + 44,
        RootAllocation::Schema => ROOT_SCHEMA.len(),
        RootAllocation::Role => 15,
    };
    let layout = Layout::array::<u8>(bytes).unwrap();
    let (expected, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        Vec::<u8>::new().try_reserve_exact(bytes).unwrap_err()
    })
    .unwrap();
    assert!(reached);
    let (error, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        store
            .put_root(root.record(), &root.regions, &retention, &mut work)
            .unwrap_err()
    })
    .unwrap();

    assert!(reached);
    assert_eq!(allocator_source(&error), &expected);
    assert!(retention.objects.lock().unwrap().is_empty());
    original.check().unwrap();
    drop(work);
    drop(original);
    assert!(quota.used() > baseline);
    drop(error);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn paid_root_logical_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RootAllocation::Logical);
}

#[test]
fn paid_root_body_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RootAllocation::Body);
}

#[test]
fn paid_root_schema_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RootAllocation::Schema);
}

#[test]
fn paid_root_role_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RootAllocation::Role);
}

#[test]
fn original_root_admission_refuses_before_logical_buffer_and_publication() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let root = captured_root(&store);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    // Leave enough for a genuine original child and the logical buffer alone,
    // but not the complete input partition. Exhaustion must precede that buffer.
    let remaining = DecodeBudget::allocation_bytes() + root.record().encoded_len() as u64 + 128;
    let competing = quota
        .resources
        .reserve(0, METADATA_BYTES - quota.used() - remaining)
        .unwrap();
    drop(original.child().unwrap());
    let retention = Retention::default();
    let (error, identity, _) = TestAllocationObserver::capture_layout_and_count(
        Layout::array::<u8>(root.record().encoded_len()).unwrap(),
        || {
            store
                .put_root(root.record(), &root.regions, &retention, &mut work)
                .unwrap_err()
        },
    );

    assert!(contains_original_quota(&error));
    assert!(identity.is_none());
    assert!(retention.objects.lock().unwrap().is_empty());
    drop(error);
    drop(competing);
    original.check().unwrap();
}

fn expected_manifest(record: &RootRecord, regions: &[TreeRef]) -> Vec<u8> {
    // Construct the previous public wire image outside the codec account.
    let logical = record.encode();
    let mut body = Vec::new();
    body.extend_from_slice(&(logical.len() as u32).to_be_bytes());
    body.extend_from_slice(&logical);
    let mut children = BTreeSet::new();
    for (index, reference) in regions.iter().enumerate() {
        body.extend_from_slice(reference.digest.as_bytes());
        body.extend_from_slice(&reference.height.to_be_bytes());
        body.extend_from_slice(&reference.pages.to_be_bytes());
        children.insert(ContentChild::new(format!("region-{index:08x}"), reference.id).unwrap());
    }
    ContentEnvelope::new(ROOT_SCHEMA, SCHEMA_VERSION, children, body)
        .unwrap()
        .canonical_bytes()
}

#[test]
fn root_publication_preserves_canonical_bytes_across_btree_splits_and_region_limit() {
    let directory = tempfile::tempdir().unwrap();
    // This separate maximum-width component has an explicit 32 MiB namespace;
    // ordinary 4 MiB fixtures and production admission limits stay unchanged.
    let quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &quota);
    let root = captured_root(&store);
    let reference = root.regions[0];
    let baseline = quota.used();

    for count in [1, 12, Limits::default().max_regions] {
        let inventory = Topology::new(
            (0..count)
                .map(|index| {
                    let name = format!("ram-{index:04x}-{}", "x".repeat(246));
                    RegionDescriptor::new(name, RegionClass::MutableMain, 4096).unwrap()
                })
                .collect(),
            Limits::default(),
        )
        .unwrap();
        let roots = inventory
            .regions()
            .iter()
            .map(|region| crucible_ram::region_tree_digest(region.geometry(), reference.digest))
            .collect::<Vec<RegionTreeDigest>>();
        let record = RootRecord::new(inventory, Scope::Exact, roots).unwrap();
        let references = vec![reference; count];
        let expected = expected_manifest(&record, &references);
        assert_eq!(record.try_encode().unwrap(), record.encode());
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let mut boundary = || Ok(());
        let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();

        let id = store
            .put_root(&record, &references, &OriginalRetention, &mut work)
            .unwrap();

        assert_eq!(
            id,
            ContentId::for_bytes(ObjectKind::ExactManifest, SCHEMA_VERSION, &expected)
        );
        let (decoded, decoded_references) = store.read_root(id, &mut work).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded_references, references);
        drop(work);
        drop(original);
        assert_eq!(quota.used(), baseline);
    }
    assert!(quota.peak.load(Ordering::SeqCst) < quota.limit);
}
