//! Conservative graph headroom and authoritative writable-leaf admission tests.

// crucible-lint: allow panic-shortcut -- adversarial fixtures panic only when their required setup or successful control operation fails.
// crucible-lint: allow rust-allow -- panic shortcuts are confined to this test module and preserve exact failure localization.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn packed_headroom_is_checked_before_publication_and_accounts_for_existing_objects() {
    let directory = TempDir::new().unwrap();
    let packed = PackedBlobBackend::open("headroom", directory.path(), 64 * 1024).unwrap();
    packed
        .admit_object_graph(&[(ObjectKind::RamTree, 65_536)])
        .unwrap();
    let bytes = b"existing";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    put_bytes(&packed, id, bytes).unwrap();

    assert!(matches!(
        packed.admit_object_graph(&[(ObjectKind::RamTree, 65_536)]),
        Err(StoreError::Quota)
    ));
    packed
        .admit_object_graph(&[(ObjectKind::RamTree, 65_535)])
        .unwrap();
    assert!(matches!(
        packed.admit_object_graph(&[(ObjectKind::RamTree, u64::MAX), (ObjectKind::RamExtent, 1)]),
        Err(StoreError::Quota)
    ));
}

#[test]
fn routed_headroom_aggregates_ram_kinds_sharing_one_index() {
    let directory = TempDir::new().unwrap();
    let packed: Arc<dyn ImmutableBlobBackend> =
        Arc::new(PackedBlobBackend::open("shared", directory.path(), 64 * 1024).unwrap());
    let routed = RoutedStore::new(
        "routed",
        BTreeMap::from([
            (ObjectKind::RamExtent, Arc::clone(&packed)),
            (ObjectKind::RamTree, packed),
        ]),
    )
    .unwrap();

    assert!(matches!(
        routed.admit_object_graph(&[
            (ObjectKind::RamExtent, 40_000),
            (ObjectKind::RamTree, 40_000)
        ]),
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
    let packed: Arc<dyn ImmutableBlobBackend> =
        Arc::new(PackedBlobBackend::open("source", directory.path(), 64 * 1024).unwrap());
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
        read_through.admit_object_graph(&[(ObjectKind::RamExtent, 65_537)]),
        Err(StoreError::Quota)
    ));
}
