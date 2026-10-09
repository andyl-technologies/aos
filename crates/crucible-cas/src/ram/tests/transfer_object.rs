//! Single authenticated-envelope transfer responses and physical corruption.

use super::*;
use crate::ram::codec::{TreeNode, decode_root_envelope, validate_page_envelope};

#[test]
fn transfer_root_and_page_encode_the_same_single_authenticated_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();

    let mut healthy = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut healthy).unwrap();
    let response = store
        .read_transfer_object_with_work(&root, &RamObjectCoordinate::Root, &mut work)
        .unwrap();
    assert_eq!(work.visits, 1);
    assert_eq!(work.io_bytes, response.canonical_bytes().len() as u64);
    assert!(response.id().authenticates(response.canonical_bytes()));
    let envelope =
        crate::content_envelope::ContentEnvelope::from_canonical_bytes(response.canonical_bytes())
            .unwrap();
    let (record, regions) = decode_root_envelope(&envelope).unwrap();
    assert_eq!(record, *root.record);
    assert_eq!(regions.as_slice(), root.regions.as_ref());
    drop(work);

    let mut work = Work::new(store.limits, &original, &mut healthy).unwrap();
    let response = store
        .read_transfer_object_with_work(
            &root,
            &RamObjectCoordinate::Page {
                region_id: "main".into(),
                page_index: 0,
            },
            &mut work,
        )
        .unwrap();
    assert_eq!(work.visits, 2, "one real leaf and one real page read");
    assert!(response.id().authenticates(response.canonical_bytes()));
    let envelope =
        crate::content_envelope::ContentEnvelope::from_canonical_bytes(response.canonical_bytes())
            .unwrap();
    let mut reference_work = Work::new(store.limits, &original, &mut healthy).unwrap();
    let TreeNode::Leaf { page, digest } = store
        .read_tree(root.regions[0], &mut reference_work)
        .unwrap()
    else {
        panic!("one real page has a canonical leaf");
    };
    assert_eq!(response.id(), page);
    assert_eq!(validate_page_envelope(&envelope, digest).unwrap(), 128);
}

#[test]
fn transfer_selected_root_and_page_reject_corrupt_physical_bytes() {
    for coordinate in [
        RamObjectCoordinate::Root,
        RamObjectCoordinate::Catalog {
            region_id: "main".into(),
            first_page: 0,
            height: 0,
        },
        RamObjectCoordinate::Page {
            region_id: "main".into(),
            page_index: 0,
        },
    ] {
        let directory = tempfile::tempdir().unwrap();
        let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
        let original = fixture_original(&store);
        let root = store
            .capture(
                topology(4096),
                Scope::Exact,
                &mut patterned,
                &Retention::default(),
                &original,
                &mut || Ok(()),
            )
            .unwrap();
        let response = store
            .read_transfer_object(&root, &coordinate, &original, &mut || Ok(()))
            .unwrap();
        let id = response.id();
        drop(response);

        // The external writer draws its descriptor and native heap allowance
        // from the same finite fixture bank before opening the connection.
        let fault_credit = quota.0.reserve(1, 8 << 20).unwrap();
        let connection = crate::content_store::fixture_sqlite_heap()
            .unwrap()
            .open_connection(
                directory.path().join("objects.sqlite3"),
                rusqlite::OpenFlags::default(),
            )
            .unwrap();
        let changed = id
            .with_encoded_text(|id| {
                connection.execute(
                    "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
                    [std::str::from_utf8(id).unwrap()],
                )
            })
            .unwrap();
        assert_eq!(changed, 1);
        drop(connection);
        drop(fault_credit);

        let error = store
            .read_transfer_object(&root, &coordinate, &original, &mut || Ok(()))
            .unwrap_err();
        let RamStoreError::Store(error) = error else {
            panic!("actual physical corruption keeps its complete storage cause");
        };
        assert!(
            matches!(error.original_failure(), StoreError::Corrupt { id: failed } if *failed == id)
        );
    }
}

#[test]
fn transfer_selected_envelope_never_exposes_bytes_after_original_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let parent = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &parent,
            &mut || Ok(()),
        )
        .unwrap();

    for coordinate in [
        RamObjectCoordinate::Root,
        RamObjectCoordinate::Catalog {
            region_id: "main".into(),
            first_page: 0,
            height: 0,
        },
        RamObjectCoordinate::Page {
            region_id: "main".into(),
            page_index: 0,
        },
    ] {
        let mut successful_polls = 0;
        let healthy = store
            .read_transfer_object(&root, &coordinate, &parent, &mut || {
                successful_polls += 1;
                Ok(())
            })
            .unwrap();
        assert!(healthy.id().authenticates(healthy.canonical_bytes()));
        drop(healthy);

        for poison_at in 1..=successful_polls {
            let operation = parent.child().unwrap();
            let mut first_refusal = None;
            let mut polls = 0;
            let result = store.read_transfer_object(&root, &coordinate, &operation, &mut || {
                polls += 1;
                if polls == poison_at {
                    first_refusal = Some(operation.charge_bytes(u64::MAX).unwrap_err());
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(polls, poison_at, "no callback follows the first refusal");
            let Err(RamStoreError::Store(error)) = &result else {
                panic!("the original typed admission cause must survive");
            };
            let StoreError::DecodeAdmission { source, .. } = error.original_failure() else {
                panic!("storage wrapping must not replace the original admission cause");
            };
            assert_eq!(Some(source), first_refusal.as_ref());
            drop(result);
            drop(first_refusal);
            drop(operation);
            assert!(parent.check().is_ok());
        }
        eprintln!("transfer_coordinate={coordinate:?} callback_positions={successful_polls}");
    }
}

#[test]
fn transfer_catalog_reemission_matches_actual_canonical_roles_and_geometry() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let parent = fixture_original(&store);
    let root = store
        .capture(
            topology(4096 * 3),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &parent,
            &mut || Ok(()),
        )
        .unwrap();

    for (first_page, height, roles) in [
        (0, 2, vec!["left", "right"]),
        (0, 1, vec!["left", "right"]),
        (2, 1, vec!["left", "right"]),
        (0, 0, vec!["page"]),
        (2, 0, vec!["page"]),
        (3, 0, vec![]),
    ] {
        let mut healthy = || Ok(());
        let mut work = Work::new(store.limits, &parent, &mut healthy).unwrap();
        let response = store
            .read_transfer_object_with_work(
                &root,
                &RamObjectCoordinate::Catalog {
                    region_id: "main".into(),
                    first_page,
                    height,
                },
                &mut work,
            )
            .unwrap();
        assert_eq!(work.visits, u64::from(3 - height));
        let envelope = store.read_envelope(response.id(), &mut work).unwrap();
        assert_eq!(response.canonical_bytes(), envelope.canonical_bytes());
        assert_eq!(
            envelope
                .children()
                .iter()
                .map(|child| child.role())
                .collect::<Vec<_>>(),
            roles
        );
        assert_eq!(
            ContentId::for_bytes(ObjectKind::RamTree, 1, response.canonical_bytes()),
            response.id()
        );
    }
}

#[test]
fn transfer_catalog_generated_full_identity_rejects_changed_reference_or_child_roles() {
    use crate::ram::codec::encode_validated_tree;

    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let parent = fixture_original(&store);
    let root = store
        .capture(
            topology(4096 * 3),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &parent,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];
    let mut healthy = || Ok(());
    let mut work = Work::new(store.limits, &parent, &mut healthy).unwrap();
    let node = store.read_tree(reference, &mut work).unwrap();
    drop(work);

    for changed in [
        crate::ram::codec::TreeRef {
            height: 1,
            ..reference
        },
        crate::ram::codec::TreeRef {
            pages: 2,
            ..reference
        },
        crate::ram::codec::TreeRef {
            digest: NodeDigest::from_bytes([42; 32]),
            ..reference
        },
        crate::ram::codec::TreeRef {
            id: ContentId::for_bytes(ObjectKind::RamExtent, 1, b"wrong kind"),
            ..reference
        },
    ] {
        let operation = parent.child().unwrap();
        let result = encode_validated_tree(changed, &node, &operation);
        assert!(
            matches!(result, Err(RamStoreError::Store(StoreError::Corrupt { id })) if id == changed.id)
        );
        drop(operation);
    }
    let TreeNode::Branch { left, right } = node else {
        panic!("the captured three-page root has distinct canonical children");
    };
    assert_ne!(left.id, right.id);
    let swapped = TreeNode::Branch {
        left: right,
        right: left,
    };
    let operation = parent.child().unwrap();
    let result = encode_validated_tree(reference, &swapped, &operation);
    assert!(
        matches!(result, Err(RamStoreError::Store(StoreError::Corrupt { id })) if id == reference.id)
    );
}

#[test]
fn transfer_catalog_wrong_actual_role_refuses_before_generated_bytes() {
    use crate::content_envelope::{ContentChild, ContentEnvelope};
    use crate::ram::codec::{TreeRef, encode_validated_tree};

    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let parent = fixture_original(&store);
    let retention = Retention::default();
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &parent,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];
    let mut healthy = || Ok(());
    let mut work = Work::new(store.limits, &parent, &mut healthy).unwrap();
    let actual = store.read_envelope(reference.id, &mut work).unwrap();
    let page = actual.children().iter().next().unwrap().id();

    let malformed_length = 30
        + "crucible.ram.tree".len()
        + 4
        + "wrong".len()
        + page.encoded_len()
        + actual.body().len();
    let input = parent.child().unwrap();
    input
        .charge_bytes(ContentEnvelope::decoding_memory_bound(malformed_length, 1).unwrap())
        .unwrap();
    let _input_scope = input.enter();
    let malformed = ContentEnvelope::new(
        "crucible.ram.tree",
        1,
        BTreeSet::from([ContentChild::new("wrong", page).unwrap()]),
        actual.body().to_vec(),
    )
    .unwrap();
    let id = store
        .put_envelope(&malformed, ObjectKind::RamTree, &retention, &mut work)
        .unwrap();
    let expected = TreeRef { id, ..reference };
    let mut emitted = false;
    let result = store.read_tree(expected, &mut work).and_then(|node| {
        emitted = true;
        encode_validated_tree(expected, &node, &parent)
    });
    assert!(
        !emitted,
        "a real malformed role never reaches canonical emission"
    );
    let Err(RamStoreError::Store(StoreError::RamReadValidation { source })) = &result else {
        panic!("actual SQL read keeps its typed validation and cleanup cause");
    };
    assert!(matches!(
        source.first_validation(),
        RamStoreError::Invalid("leaf child role")
    ));
    let mut complete: &(dyn std::error::Error + 'static) = source.storage_failure();
    let scope = loop {
        if let Some(scope) = complete.downcast_ref::<crate::content_store::SqliteScopeError>() {
            break scope;
        }
        complete = complete.source().unwrap();
    };
    assert_eq!(
        scope.outcome(),
        crate::content_store::SqliteCommitOutcome::NotCommitted
    );
    assert!(scope.rollback_failure().is_none());
    assert!(scope.restoration_failure().is_none());
}

#[test]
fn transfer_raw_corruption_precedes_an_unobserved_late_eof_refusal() {
    for coordinate in [
        RamObjectCoordinate::Root,
        RamObjectCoordinate::Page {
            region_id: "main".into(),
            page_index: 0,
        },
    ] {
        let directory = tempfile::tempdir().unwrap();
        let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
        let original = fixture_original(&store);
        let root = store
            .capture(
                topology(128),
                Scope::Exact,
                &mut patterned,
                &Retention::default(),
                &original,
                &mut || Ok(()),
            )
            .unwrap();
        let mut healthy_polls = 0;
        let healthy = store
            .read_transfer_object(&root, &coordinate, &original, &mut || {
                healthy_polls += 1;
                Ok(())
            })
            .unwrap();
        let id = healthy.id();
        drop(healthy);
        // The last two native edges discharge EOF and finish clean scope
        // acceptance. A known full-body hash mismatch precedes both edges.
        let late_eof = healthy_polls - 1;
        let mut late_polls = 0;
        let late = store
            .read_transfer_object(&root, &coordinate, &original, &mut || {
                late_polls += 1;
                if late_polls == late_eof {
                    Err(RamStoreError::Canceled)
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        let RamStoreError::Store(StoreError::RamReadBoundary { source }) = &late else {
            panic!("actual checked EOF keeps its evidenced original boundary failure");
        };
        assert!(matches!(
            source.first_boundary(),
            Some(RamStoreError::Canceled)
        ));
        assert_transfer_clean_scope(source.storage_failure());
        assert_eq!(late_polls, late_eof);
        drop(late);

        let fault_credit = quota.0.reserve(1, 8 << 20).unwrap();
        let connection = crate::content_store::fixture_sqlite_heap()
            .unwrap()
            .open_connection(
                directory.path().join("objects.sqlite3"),
                rusqlite::OpenFlags::default(),
            )
            .unwrap();
        assert_eq!(
            id.with_encoded_text(|id| connection.execute(
                "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
                [std::str::from_utf8(id).unwrap()],
            ))
            .unwrap(),
            1
        );
        drop(connection);
        drop(fault_credit);

        let mut corrupt_polls = 0;
        let corrupt = store
            .read_transfer_object(&root, &coordinate, &original, &mut || {
                corrupt_polls += 1;
                if corrupt_polls == late_eof {
                    Err(RamStoreError::Canceled)
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        let RamStoreError::Store(error) = &corrupt else {
            panic!("a physical hash mismatch retains its complete store failure");
        };
        assert!(
            matches!(error.original_failure(), StoreError::Corrupt { id: actual } if *actual == id)
        );
        assert!(
            corrupt_polls < late_eof,
            "no later EOF callback runs after known corruption"
        );
        assert_transfer_clean_scope(match error {
            StoreError::RamValidation { source } => source.storage_failure(),
            _ => panic!("the same Work seals its first physical failure"),
        });
        eprintln!(
            "raw_transfer={coordinate:?} healthy={healthy_polls} known_corrupt={corrupt_polls} late_eof={late_eof}"
        );
    }
}

#[test]
fn transfer_typed_root_decode_waits_for_actual_eof_and_native_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let retention = Retention::default();
    let root = store
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let mut healthy = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut healthy).unwrap();
    let actual = store.read_envelope(root.object_id(), &mut work).unwrap();
    let input = original.child().unwrap();
    input
        .charge_bytes(
            crate::content_envelope::ContentEnvelope::decoding_memory_bound(
                30 + actual.schema_name().len()
                    + actual.body().len()
                    + actual
                        .children()
                        .iter()
                        .map(|child| 4 + child.role().len() + child.id().encoded_len())
                        .sum::<usize>(),
                actual.children().len(),
            )
            .unwrap(),
        )
        .unwrap();
    let scope = input.enter();
    let malformed = crate::content_envelope::ContentEnvelope::new(
        "crucible.ram.roox",
        1,
        actual.children().clone(),
        actual.body().to_vec(),
    )
    .unwrap();
    let id = store
        .put_envelope(&malformed, ObjectKind::ExactManifest, &retention, &mut work)
        .unwrap();
    drop(work);
    drop(scope);
    drop(input);
    drop(actual);
    let mut malformed_root = root.clone();
    malformed_root.lease = retention.retain_root(id).unwrap();

    let mut successful_eof_polls = 0;
    let decoded = store
        .read_transfer_object(
            &malformed_root,
            &RamObjectCoordinate::Root,
            &original,
            &mut || {
                successful_eof_polls += 1;
                Ok(())
            },
        )
        .unwrap_err();
    let RamStoreError::Store(StoreError::RamValidation { source }) = &decoded else {
        panic!("post-EOF typed root failure stays distinct from supervision");
    };
    assert!(matches!(
        source.storage_failure(),
        RamStoreError::Invalid("root envelope")
    ));
    drop(decoded);

    let mut refused_polls = 0;
    let refused = store
        .read_transfer_object(
            &malformed_root,
            &RamObjectCoordinate::Root,
            &original,
            &mut || {
                refused_polls += 1;
                if refused_polls == successful_eof_polls - 1 {
                    Err(RamStoreError::Canceled)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    let RamStoreError::Store(StoreError::RamReadBoundary { source }) = &refused else {
        panic!("the actual checked EOF refusal precedes allocating typed decoding");
    };
    assert!(matches!(
        source.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert_transfer_clean_scope(source.storage_failure());
    assert_eq!(refused_polls, successful_eof_polls - 1);
}

fn assert_transfer_clean_scope(error: &RamStoreError) {
    use std::error::Error;
    let mut cause: &(dyn Error + 'static) = error;
    loop {
        if let Some(scope) = cause.downcast_ref::<crate::content_store::SqliteScopeError>() {
            assert_eq!(
                scope.outcome(),
                crate::content_store::SqliteCommitOutcome::NotCommitted
            );
            assert!(scope.rollback_failure().is_none());
            assert!(scope.restoration_failure().is_none());
            return;
        }
        cause = cause
            .source()
            .expect("the actual entered scope and cleanup remain owned");
    }
}
