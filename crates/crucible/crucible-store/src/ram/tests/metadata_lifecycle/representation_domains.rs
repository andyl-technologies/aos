//! Stored page authentication and logical RAM commitments use distinct domains.
//!
//! Real directory publication supplies valid CAS objects, including adversarial
//! objects whose metadata agrees throughout the catalog but lies about bytes.
//! Finite component admission covers caller-owned inputs and outputs; these
//! controls do not grant native execution or whole-world readiness.

use super::*;
use crate::ram::codec::{PAGE_SCHEMA, SCHEMA_VERSION, TreeNode};
use crucible_ram::{PageDigest, RootRecord, region_tree_digest};

fn caller_account(quota: &Arc<ObservedQuota>) -> DecodeBudget {
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    original
}

fn assert_stored_identity(store: &RamStore, id: ContentId, original: &DecodeBudget) {
    let source = store
        .backend
        .read_with_boundary(original, id, None, &mut || Ok(()))
        .unwrap();
    let canonical = source
        .read_all_with_boundary(original, 8192, &mut || Ok(()))
        .unwrap();
    assert!(id.authenticates(&canonical));
}

#[test]
fn stored_page_identity_and_logical_digest_have_distinct_preimages() {
    for class in [
        RegionClass::MutableMain,
        RegionClass::MutableDevice,
        RegionClass::ImmutableImage,
        RegionClass::ContinuationPrivate,
    ] {
        for length in [1, 17, 4096] {
            let directory = tempfile::tempdir().unwrap();
            let quota = ObservedQuota::with_limit(64 << 20);
            let store = directory_store(directory.path(), &quota);
            let baseline = quota.used();
            let original = caller_account(&quota);
            let admitted = quota.used();
            let retention = Retention::default();
            let region = RegionDescriptor::new("main", class, length).unwrap();
            let topology = Topology::new(vec![region.clone()], Limits::default()).unwrap();
            let root = store
                .capture(
                    topology,
                    Scope::Exact,
                    &mut patterned,
                    &retention,
                    &original,
                    &mut || Ok(()),
                )
                .unwrap();
            let mut boundary = || Ok(());
            let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
            let TreeNode::Leaf { page, digest } =
                store.read_tree(root.regions[0], &mut work).unwrap()
            else {
                panic!("one-page region must have a leaf catalog");
            };
            drop(work);

            assert_stored_identity(&store, page, &original);
            let bytes = store
                .read_page(&root, "main", 0, &original, &mut || Ok(()))
                .unwrap();
            assert_eq!(digest, PageDigest::hash(&bytes).unwrap());
            assert_ne!(digest, PageDigest::from_bytes(page.digest()));
            assert!(!page.authenticates(&bytes));
            let independent =
                crucible_ram::oracle::recompute_region(&region, 1, |_, index, bytes| {
                    bytes.fill(index as u8);
                    Ok(())
                })
                .unwrap();
            assert_eq!(root.record().region_roots(), &[independent]);

            drop(bytes);
            drop(root);
            assert!(quota.used() >= admitted);
            drop(original);
            assert_eq!(quota.used(), baseline);
        }
    }
}

fn assert_logical_page_refusal(error: &RamStoreError) {
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(cause) = current {
        if matches!(
            cause.downcast_ref::<RamStoreError>(),
            Some(RamStoreError::Invalid("logical page digest"))
        ) {
            return;
        }
        current = cause.source();
    }
    panic!("expected actual logical page digest refusal: {error:?}");
}

#[test]
fn valid_cas_and_consistent_catalog_cannot_substitute_storage_hash_for_page_digest() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::with_limit(64 << 20);
    let store = directory_store(directory.path(), &quota);
    let baseline = quota.used();
    let original = caller_account(&quota);
    let admitted = quota.used();
    let retention = Retention::default();
    let region = RegionDescriptor::new("main", RegionClass::MutableMain, 17).unwrap();
    let topology = Topology::new(vec![region.clone()], Limits::default()).unwrap();
    let bytes = [0x29; 17];
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let (genuine_page, genuine_digest) = store.put_page(&bytes, &retention, &mut work).unwrap();
    let substituted = PageDigest::from_bytes(genuine_page.digest());
    assert_ne!(substituted, genuine_digest);

    // All recorded logical metadata agrees with the substitution, including
    // the page envelope. Only hashing the actual valid bytes exposes the lie.
    let mut body = Vec::with_capacity(36 + bytes.len());
    body.extend_from_slice(substituted.as_bytes());
    body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&bytes);
    let envelope =
        ContentEnvelope::new(PAGE_SCHEMA, SCHEMA_VERSION, BTreeSet::new(), body).unwrap();
    let page = store
        .put_envelope(&envelope, ObjectKind::RamExtent, &retention, &mut work)
        .unwrap();
    let leaf = store
        .put_tree(
            &TreeNode::Leaf {
                page,
                digest: substituted,
            },
            0,
            1,
            &retention,
            &mut work,
        )
        .unwrap();
    let record = RootRecord::new(
        topology,
        Scope::Exact,
        vec![region_tree_digest(region.geometry(), leaf.digest)],
    )
    .unwrap();
    let id = store
        .put_root(&record, &[leaf], &retention, &mut work)
        .unwrap();
    drop(work);

    for object in [genuine_page, page, leaf.id, id] {
        assert_stored_identity(&store, object, &original);
    }
    let root = store
        .open(
            retention.retain_root(id).unwrap(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(root.record(), &record);
    // Opening a catalog is deliberately weaker than proving page possession.
    let error = store.verify(&root, &original, &mut || Ok(())).unwrap_err();
    assert_logical_page_refusal(&error);
    drop(error);
    let error = store
        .read_page(&root, "main", 0, &original, &mut || Ok(()))
        .unwrap_err();
    assert_logical_page_refusal(&error);
    drop(error);
    let mut delivered = 0;
    let error = store
        .visit_pages(&root, &original, &mut || Ok(()), &mut |_, _, _| {
            delivered += 1;
            Ok(())
        })
        .unwrap_err();
    assert_logical_page_refusal(&error);
    assert_eq!(delivered, 0, "unverified bytes cannot reach the visitor");

    drop(error);
    drop(root);
    drop(record);
    drop(envelope);
    assert!(quota.used() >= admitted);
    drop(original);
    assert_eq!(quota.used(), baseline);
}
