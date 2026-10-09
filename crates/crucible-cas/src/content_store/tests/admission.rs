//! Paged counter bounds and authoritative writable-leaf object admission.

// crucible-lint: allow panic-shortcut -- adversarial fixtures panic only when their required setup or successful control operation fails.
// crucible-lint: allow rust-allow -- panic shortcuts are confined to this test module and preserve exact failure localization.
#![allow(clippy::unwrap_used)]

use super::*;

fn quota_packed(root: &Path, maximum_objects: u64) -> Arc<dyn ImmutableBlobBackend> {
    let quota = node_id("object-quota");
    let packed = node_id("packed");
    Arc::new(
        StoreGraph::build(StoreGraphConfig {
            gc_mark_root: None,
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::RamTree, ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    quota,
                    StoreNodeSpec::LogicalQuota {
                        child: packed.clone(),
                        state_root: root.join("quota-state"),
                        maximum_objects,
                        maximum_logical_bytes: 64 * 1024,
                    },
                ),
                (
                    packed,
                    StoreNodeSpec::Packed {
                        root: root.join("packs"),
                        target_pack_bytes: 64 * 1024,
                    },
                ),
            ]),
        })
        .unwrap(),
    )
}

#[test]
fn packed_headroom_is_checked_before_publication_and_accounts_for_existing_objects() {
    let directory = TempDir::new().unwrap();
    let packed =
        PackedBlobBackend::open("headroom", directory.path().join("raw"), 64 * 1024).unwrap();
    packed
        .admit_object_graph(&[(ObjectKind::RamTree, 65_536)])
        .unwrap();
    let bytes = b"existing";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    put_bytes(&packed, id, bytes).unwrap();

    // Paged format2 has no flat-index ceiling. It still refuses overflow of
    // the existing placement and pack record counters before publication.
    packed
        .admit_object_graph(&[(ObjectKind::RamTree, 65_536)])
        .unwrap();
    packed
        .admit_object_graph(&[(ObjectKind::RamTree, u64::MAX / 2 - 1)])
        .unwrap();
    assert!(matches!(
        packed.admit_object_graph(&[(ObjectKind::RamTree, u64::MAX / 2)]),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        packed.admit_object_graph(&[(ObjectKind::RamTree, u64::MAX), (ObjectKind::RamExtent, 1)]),
        Err(StoreError::Quota)
    ));

    // A finite object policy is a real LogicalQuota owner, independently of
    // target pack size or page geometry. Its existing object consumes a slot.
    let quota = quota_packed(&directory.path().join("bounded"), 3);
    quota
        .admit_object_graph(&[(ObjectKind::RamTree, 3)])
        .unwrap();
    put_bytes(quota.as_ref(), id, bytes).unwrap();
    quota
        .admit_object_graph(&[(ObjectKind::RamTree, 2)])
        .unwrap();
    assert!(matches!(
        quota.admit_object_graph(&[(ObjectKind::RamTree, 3)]),
        Err(StoreError::Quota)
    ));
    assert!(quota.contains(id).unwrap());
    // Omitting the quota owner admits that same count on the real raw leaf.
    packed
        .admit_object_graph(&[(ObjectKind::RamTree, 3)])
        .unwrap();
}

#[test]
fn routed_headroom_aggregates_ram_kinds_sharing_one_index() {
    let directory = TempDir::new().unwrap();
    let packed = quota_packed(directory.path(), 5);
    for kind in [ObjectKind::RamExtent, ObjectKind::RamTree] {
        packed.admit_object_graph(&[(kind, 3)]).unwrap();
    }
    let routed = RoutedStore::new(
        "routed",
        BTreeMap::from([
            (ObjectKind::RamExtent, Arc::clone(&packed)),
            (ObjectKind::RamTree, packed),
        ]),
    )
    .unwrap();

    routed
        .admit_object_graph(&[(ObjectKind::RamExtent, 2), (ObjectKind::RamTree, 3)])
        .unwrap();
    assert!(matches!(
        routed.admit_object_graph(&[(ObjectKind::RamExtent, 3), (ObjectKind::RamTree, 3)]),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        routed.admit_object_graph(&[(ObjectKind::ExactManifest, 1)]),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn read_cache_capacity_never_grants_or_denies_authoritative_write_headroom() {
    let directory = TempDir::new().unwrap();
    let packed = quota_packed(directory.path(), 8);
    let cache: Arc<dyn ImmutableBlobBackend> = Arc::new(MemoryBlobBackend::new("cache", 1));
    assert!(matches!(
        cache.admit_object_graph(&[(ObjectKind::RamExtent, 1)]),
        Err(StoreError::Unsupported { .. })
    ));
    let read_through = ReadThroughStore::new("read-through", cache, packed);

    read_through
        .admit_object_graph(&[(ObjectKind::RamExtent, 8)])
        .unwrap();
    assert!(matches!(
        read_through.admit_object_graph(&[(ObjectKind::RamExtent, 9)]),
        Err(StoreError::Quota)
    ));
}
