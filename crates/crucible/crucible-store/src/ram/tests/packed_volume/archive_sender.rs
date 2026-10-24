//! Actual archive sender manifest reuse, request limits and refusal custody.
//!
//! These tests borrow the parent's real Packed fixture and unchanged finite
//! account. They distinguish retained error debt from physical resource leaks.

use super::*;

#[test]
fn packed_archive_sender_reuses_paid_manifest_and_allows_same_store_archive() {
    use crucible_qemu_protocol::ram_transfer::{
        RamTransferControl, RamTransferLimits, RamTransferMessage, RamTransferNodeCoordinate,
    };

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 8);
    let tree = root.regions[0];
    let child = {
        let mut boundary = || Ok(());
        let mut work = Work::new(fixture.store.limits, &fixture.original, &mut boundary).unwrap();
        let TreeNode::Branch { left, .. } = fixture.store.read_tree(tree, &mut work).unwrap()
        else {
            panic!("eight pages have a real child catalog");
        };
        left
    };
    let baseline = fixture.quota.0.usage().unwrap();
    let world = ContentId::for_bytes(
        ObjectKind::ExactManifest,
        6,
        b"bounded archive session owner",
    );
    let operation = [93; 32];
    let mut sender = RamTransferSender::new(
        fixture.store.clone(),
        root.clone(),
        operation,
        world,
        "packed-session-destination",
        1,
        RamTransferLimits {
            objects: 100,
            bytes: 1 << 20,
            chunk_bytes: 64 << 10,
        },
        &fixture.original,
    )
    .unwrap();
    let root_response = sender
        .respond(
            RamTransferMessage {
                operation,
                control: RamTransferControl::WantNode {
                    coordinate: RamTransferNodeCoordinate::Root,
                    object: root.object_id().to_string(),
                },
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(sender.canonical_manifest_reads_for_test(), 1);
    drop(root_response);
    let catalog_response = sender
        .respond(
            RamTransferMessage {
                operation,
                control: RamTransferControl::WantNode {
                    coordinate: RamTransferNodeCoordinate::Catalog {
                        region_id: "main".into(),
                        first_page: 0,
                        height: tree.height,
                    },
                    object: tree.id.to_string(),
                },
            },
            &mut || Ok(()),
        )
        .unwrap();
    // Capture flushes the page/catalog pack before publishing the root in a
    // separate pack. Crossing that physical placement must authenticate again.
    assert_eq!(sender.canonical_manifest_reads_for_test(), 2);
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop(catalog_response);

    let child_response = sender
        .respond(
            RamTransferMessage {
                operation,
                control: RamTransferControl::WantNode {
                    coordinate: RamTransferNodeCoordinate::Catalog {
                        region_id: "main".into(),
                        first_page: 0,
                        height: child.height,
                    },
                    object: child.id.to_string(),
                },
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        sender.canonical_manifest_reads_for_test(),
        2,
        "the distinct child shares the real catalog pack's paid manifest"
    );
    drop(child_response);

    // The first source remains live while the real coordinator reads/publishes
    // the same namespace. No retained source lock may block this archive.
    let retention = fixture.retention();
    let archive = fixture
        .store
        .transfer_archive_to(
            &root,
            world,
            &fixture.store,
            "same-store-session-destination",
            [94; 32],
            &retention,
            &fixture.original,
            &fixture.original,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(archive.root().object_id(), root.object_id());
    assert_eq!(archive.report().copied_objects, 0);
    assert!(archive.report().authenticated_existing_objects > 0);
    drop((archive, retention));
    let closed = sender
        .respond(
            RamTransferMessage {
                operation,
                control: RamTransferControl::ClosureStored {
                    ram_root: root.object_id().to_string(),
                },
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(sender.canonical_manifest_reads_for_test(), 0);
    drop((closed, sender));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn packed_archive_sender_request_limit_closes_cache_without_extra_source_read() {
    use crucible_qemu_protocol::ram_transfer::{
        RamTransferControl, RamTransferLimits, RamTransferMessage, RamTransferNodeCoordinate,
    };

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 8);
    let baseline = fixture.quota.0.usage().unwrap();
    let operation = [95; 32];
    let mut sender = RamTransferSender::new(
        fixture.store.clone(),
        root.clone(),
        operation,
        ContentId::for_bytes(ObjectKind::ExactManifest, 6, b"bounded archive limit owner"),
        "packed-session-destination",
        1,
        RamTransferLimits {
            objects: 1,
            bytes: 1 << 20,
            chunk_bytes: 64 << 10,
        },
        &fixture.original,
    )
    .unwrap();
    let want = RamTransferMessage {
        operation,
        control: RamTransferControl::WantNode {
            coordinate: RamTransferNodeCoordinate::Root,
            object: root.object_id().to_string(),
        },
    };
    drop(sender.respond(want.clone(), &mut || Ok(())).unwrap());
    assert_eq!(sender.canonical_manifest_reads_for_test(), 1);
    let visits = sender.state_for_test().1;
    let error = sender.respond(want.clone(), &mut || Ok(())).err().unwrap();
    let RamStoreError::Store(StoreError::RamValidation { source: first }) = error else {
        panic!("the request limit retains the operation's prepaid validation cause");
    };
    assert!(matches!(
        first.storage_failure(),
        RamStoreError::Limit("transfer requests")
    ));
    assert_eq!(sender.state_for_test().1, visits);
    assert_eq!(sender.canonical_manifest_reads_for_test(), 0);
    let retry = sender
        .respond(want, &mut || {
            panic!("a failed sender cannot poll or read again")
        })
        .err()
        .unwrap();
    let RamStoreError::Store(StoreError::RamValidation { source: retry }) = retry else {
        panic!("retry returns the same retained validation cause");
    };
    assert_eq!(first, retry);
    assert_eq!(sender.state_for_test().1, visits);
    drop(sender);
    assert_eq!(
        fixture.quota.0.usage().unwrap(),
        (
            baseline.0,
            baseline.1
                + PreparedRamFailure::<std::convert::Infallible>::allocation_bytes().unwrap()
        ),
        "the actual retained cause keeps its existing prepayment"
    );
    drop((first, retry));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn packed_archive_sender_warm_cache_does_not_admit_a_forbidden_catalog_kind() {
    use crucible_qemu_protocol::ram_transfer::{
        RamTransferControl, RamTransferLimits, RamTransferMessage, RamTransferNodeCoordinate,
    };

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 8);
    let restricted = Fixture::with_admitted(
        directory.path(),
        fixture.quota.clone(),
        BTreeSet::from([
            ObjectKind::ExactManifest,
            ObjectKind::RamExtent,
            ObjectKind::Trace,
        ]),
    );
    let baseline = fixture.quota.0.usage().unwrap();
    let operation = [96; 32];
    let mut sender = RamTransferSender::new(
        restricted.store.clone(),
        root.clone(),
        operation,
        ContentId::for_bytes(
            ObjectKind::ExactManifest,
            6,
            b"bounded archive admission owner",
        ),
        "packed-session-destination",
        1,
        RamTransferLimits {
            objects: 100,
            bytes: 1 << 20,
            chunk_bytes: 64 << 10,
        },
        &restricted.original,
    )
    .unwrap();
    drop(
        sender
            .respond(
                RamTransferMessage {
                    operation,
                    control: RamTransferControl::WantNode {
                        coordinate: RamTransferNodeCoordinate::Root,
                        object: root.object_id().to_string(),
                    },
                },
                &mut || Ok(()),
            )
            .unwrap(),
    );
    assert_eq!(sender.canonical_manifest_reads_for_test(), 1);
    let tree = root.regions[0];
    let visits = sender.state_for_test().1;
    let index_before =
        std::fs::read(directory.path().join("objects/.packed-admin/index-v1")).unwrap();
    let error = sender
        .respond(
            RamTransferMessage {
                operation,
                control: RamTransferControl::WantNode {
                    coordinate: RamTransferNodeCoordinate::Catalog {
                        region_id: "main".into(),
                        first_page: 0,
                        height: tree.height,
                    },
                    object: tree.id.to_string(),
                },
            },
            &mut || Ok(()),
        )
        .err()
        .unwrap();
    let RamStoreError::Store(stored) = &error else {
        panic!("{error:?}");
    };
    assert!(matches!(
        stored.original_failure(),
        StoreError::InvalidGraph {
            violation: crate::content_store::GraphViolation::RouteCoverage,
            ..
        }
    ));
    assert_eq!(sender.state_for_test().1, visits);
    assert_eq!(
        std::fs::read(directory.path().join("objects/.packed-admin/index-v1")).unwrap(),
        index_before
    );
    assert_eq!(sender.canonical_manifest_reads_for_test(), 0);
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop(sender);
    assert_eq!(
        fixture.quota.0.usage().unwrap(),
        (
            baseline.0,
            baseline.1
                + PreparedRamFailure::<std::convert::Infallible>::allocation_bytes().unwrap()
        ),
        "the returned forbidden-kind cause outlives its sender"
    );
    drop(error);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}
