//! Ordered updates retain incoming identifier storage instead of cloning it.
//!
//! Complete capture independently supplies the expected canonical successor.
//! Inputs precede finite caller admission; allocation observations establish
//! neither native resource authority nor performance qualification.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use std::alloc::Layout;

fn identifiers(unicode: bool) -> [String; 2] {
    let suffix = if unicode {
        "é".repeat(127)
    } else {
        "x".repeat(254)
    };
    [format!("a{suffix}"), format!("z{suffix}")]
}

fn ordered_updates_reuse_identifiers(unicode: bool) {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::with_limit(64 << 20);
    let store = directory_store(directory.path(), &quota);
    let retention = Retention::default();
    let [first, last] = identifiers(unicode);
    assert_eq!(first.len(), 255);
    assert_eq!(last.len(), 255);
    let topology = Topology::new(
        vec![
            RegionDescriptor::new(first.clone(), RegionClass::MutableMain, 8193).unwrap(),
            RegionDescriptor::new(last.clone(), RegionClass::MutableDevice, 8193).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    let root = store
        .capture(
            topology.clone(),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let expected = store
        .capture(
            topology,
            Scope::Exact,
            &mut |region, index, bytes| {
                patterned(region, index, bytes)?;
                match (region.id(), index) {
                    (id, 0) if id == first => bytes.fill(99),
                    (id, 2) if id == first => bytes.fill(101),
                    (id, 1) if id == last => bytes.fill(103),
                    _ => {}
                }
                Ok(())
            },
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let changes = [
        RamPageChange {
            region_id: first.clone(),
            page_index: 0,
            bytes: vec![99; 4096],
        },
        RamPageChange {
            region_id: first.clone(),
            page_index: 2,
            bytes: vec![101],
        },
        RamPageChange {
            region_id: last.clone(),
            page_index: 1,
            bytes: vec![103; 4096],
        },
    ];
    let baseline = quota.used();
    let original = fixture_original(&store);
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = quota.used();

    let (result, identifier_copy, counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::array::<u8>(255).unwrap(), || {
            store.update(&root, changes, &retention, &original, &mut || Ok(()))
        });
    let updated = result.unwrap();

    assert!(!counts.overflow);
    assert!(
        identifier_copy.is_none(),
        "ordered updates allocated another maximum-byte identifier; unicode={unicode}"
    );
    assert_eq!(updated.object_id(), expected.object_id());
    assert_eq!(updated.record(), expected.record());
    assert_ne!(updated.logical_digest(), root.logical_digest());
    assert!(quota.used() >= admitted);
    for (id, index, value, length) in [
        (&first, 0, 99, 4096),
        (&first, 2, 101, 1),
        (&last, 1, 103, 4096),
    ] {
        let bytes = store
            .read_page(&updated, id, index, &original, &mut || Ok(()))
            .unwrap();
        assert_eq!(bytes.as_ref(), vec![value; length]);
        let predecessor = store
            .read_page(&root, id, index, &original, &mut || Ok(()))
            .unwrap();
        assert_eq!(predecessor.as_ref(), vec![index as u8; length]);
    }
    drop(updated);
    drop(original);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn ordered_updates_reuse_incoming_maximum_byte_ascii_identifiers() {
    ordered_updates_reuse_identifiers(false);
}

#[test]
fn ordered_updates_reuse_incoming_maximum_byte_utf8_identifiers() {
    ordered_updates_reuse_identifiers(true);
}

#[test]
fn coordinate_or_stream_refusal_cannot_publish_a_partial_successor() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::with_limit(64 << 20);
    let store = directory_store(directory.path(), &quota);
    let retention = Retention::default();
    let [first, last] = identifiers(true);
    let topology = Topology::new(
        vec![
            RegionDescriptor::new(first.clone(), RegionClass::MutableMain, 8192).unwrap(),
            RegionDescriptor::new(last.clone(), RegionClass::MutableDevice, 8192).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
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
    let published_roots = || {
        retention
            .objects
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|id| id.kind() == ObjectKind::ExactManifest)
            .collect::<BTreeSet<_>>()
    };
    let before = published_roots();
    assert_eq!(before, BTreeSet::from([root.object_id()]));

    for (initial_id, initial_page, next_id, next_page, truncated) in [
        (&first, 0, &first, 0, false),
        (&first, 1, &first, 0, false),
        (&last, 0, &first, 0, false),
        (&first, 0, &last, 0, true),
    ] {
        let mut changes = [
            RamPageChange {
                region_id: initial_id.clone(),
                page_index: initial_page,
                bytes: vec![99; 4096],
            },
            RamPageChange {
                region_id: next_id.clone(),
                page_index: next_page,
                bytes: vec![101; 4096],
            },
        ]
        .into_iter();
        let baseline = quota.used();
        let original = fixture_original(&store);
        original
            .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
            .unwrap();
        let admitted = quota.used();
        let mut calls = 0;
        let result = store.update_with_reader(
            &root,
            &mut || {
                calls += 1;
                if truncated && calls == 2 {
                    return Err(RamStoreError::Invalid("original coordinate stream ended"));
                }
                Ok(changes.next())
            },
            &retention,
            &original,
            &mut || Ok(()),
        );
        let error = result.unwrap_err();

        assert_eq!(calls, 2);
        assert!(matches!(
            error,
            RamStoreError::Invalid(message)
                if message == if truncated {
                    "original coordinate stream ended"
                } else {
                    "nonascending page changes"
                }
        ));
        assert_eq!(published_roots(), before);
        assert!(quota.used() >= admitted);
        let predecessor = store
            .read_page(&root, initial_id, initial_page, &original, &mut || Ok(()))
            .unwrap();
        assert_eq!(predecessor.as_ref(), vec![initial_page as u8; 4096]);
        drop(predecessor);
        drop(error);
        drop(original);
        assert_eq!(quota.used(), baseline);
    }
}
