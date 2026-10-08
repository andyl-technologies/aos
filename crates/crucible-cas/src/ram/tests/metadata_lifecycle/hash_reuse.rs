//! Compares exact publication identities and updates with their canonical inputs.

use crate::content_envelope::{ContentChild, ContentEnvelope};

use super::*;

fn original_ram_failure(error: &RamStoreError) -> &RamStoreError {
    match error {
        RamStoreError::Boundary(cause) => original_ram_failure(
            cause
                .first_boundary()
                .unwrap_or_else(|| cause.storage_failure()),
        ),
        RamStoreError::Store(storage) => match storage.original_failure() {
            StoreError::RamValidation { source } => original_ram_failure(source.storage_failure()),
            _ => error,
        },
        error => error,
    }
}

#[test]
fn publication_hashes_match_the_former_envelope_identity_path() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let baseline = quota.used();
    let retention = Retention::default();

    for kind in [
        ObjectKind::RamExtent,
        ObjectKind::RamTree,
        ObjectKind::ExactManifest,
    ] {
        for version in [1, 2] {
            for child_count in 0..=2 {
                for length in [0, 1, 19, 1024] {
                    let loan = parent.reserve_scratch_bytes(16 * 1024).unwrap();
                    let children = (0..child_count)
                        .map(|index| {
                            ContentChild::new(
                                format!("child-{index}"),
                                ContentId::for_bytes(ObjectKind::RamExtent, 1, &[index]),
                            )
                            .unwrap()
                        })
                        .collect();
                    let envelope = ContentEnvelope::new(
                        "crucible.hash-reuse",
                        version,
                        children,
                        vec![7; length],
                    )
                    .unwrap();
                    // This unchanged generic emitter is the former RAM put's
                    // identity computation, independently of its admitted Vec.
                    let former = envelope.content_id(kind);
                    let mut boundary = || Ok(());
                    let mut work = Work::new(store.limits, &parent, &mut boundary).unwrap();
                    let result = store.put_envelope(&envelope, kind, &retention, &mut work);
                    if version == 1 && kind == ObjectKind::RamExtent && child_count != 0 {
                        let error = result.unwrap_err();
                        assert!(
                            matches!(
                                original_ram_failure(&error),
                                RamStoreError::Envelope(
                                    crate::content_envelope::ContentEnvelopeError::LimitExceeded {
                                        limit: "child-count"
                                    }
                                )
                            ),
                            "{error:?}"
                        );
                        let RamStoreError::Store(StoreError::DirectoryScope { source }) = &error
                        else {
                            panic!(
                                "actual published directory outcome must remain owned: {error:?}"
                            )
                        };
                        assert_eq!(source.outcome().published_objects, 1);
                        assert_eq!(source.outcome().durable_objects, 1);
                        assert!(!source.outcome().durability_uncertain);
                        assert!(source.cleanup_failure().is_none());
                        assert!(retention.objects.lock().unwrap().contains(&former));
                        drop(error);
                    } else if version == 1 {
                        assert_eq!(result.unwrap(), former);
                    } else {
                        let error = result.unwrap_err();
                        assert!(matches!(
                            original_ram_failure(&error),
                            RamStoreError::Invalid("RAM storage schema")
                        ));
                        let RamStoreError::Store(StoreError::DirectoryScope { source }) = &error
                        else {
                            panic!("published invalid schema keeps its actual outcome: {error:?}")
                        };
                        assert_eq!(source.outcome().published_objects, 1);
                        assert_eq!(source.outcome().durable_objects, 1);
                        assert!(!source.outcome().durability_uncertain);
                        assert!(source.cleanup_failure().is_none());
                        assert!(retention.objects.lock().unwrap().contains(&former));
                        drop(error);
                    }
                    drop(work);
                    drop(envelope);
                    drop(loan);
                    assert_eq!(quota.used(), baseline);
                }
            }
        }
    }

    drop(scope);
    drop(parent);
    drop(store);
    assert_eq!(quota.used(), 0);
}

#[test]
fn changed_unchanged_and_reverted_pages_match_independent_full_capture() {
    let directory = tempfile::tempdir().unwrap();
    let reference_directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let reference = directory_store(reference_directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let retention = Retention::default();
    let original = store
        .capture(
            topology(3 * 4096 + 19),
            Scope::Exact,
            &mut patterned,
            &retention,
            &parent,
            &mut || Ok(()),
        )
        .unwrap();
    let mut root = original.clone();
    let mut expected_pages = [0, 1, 2, 3];

    for (index, value, length) in [(1, 91, 4096), (1, 91, 4096), (3, 41, 19), (1, 1, 4096)] {
        let prior = root.object_id();
        let unchanged = expected_pages[index as usize] == value;
        expected_pages[index as usize] = value;
        root = store
            .update(
                &root,
                [RamPageChange {
                    region_id: "main".into(),
                    page_index: index,
                    bytes: vec![value; length],
                }],
                &retention,
                &parent,
                &mut || Ok(()),
            )
            .unwrap();
        let expected = reference
            .capture(
                topology(3 * 4096 + 19),
                Scope::Exact,
                &mut |_, page, bytes| {
                    bytes.fill(expected_pages[page as usize]);
                    Ok(())
                },
                &retention,
                &parent,
                &mut || Ok(()),
            )
            .unwrap();
        assert_eq!(root.object_id(), expected.object_id());
        assert_eq!(root.logical_digest(), expected.logical_digest());
        if unchanged {
            assert_eq!(prior, root.object_id());
        }
    }
    assert_eq!(
        store
            .read_page(&original, "main", 1, &parent, &mut || Ok(()))
            .unwrap(),
        vec![1; 4096]
    );
    drop(root);
    drop(original);
    drop(scope);
    drop(parent);
    drop(reference);
    drop(store);
    assert_eq!(quota.used(), 0);
}

#[test]
fn corrupt_old_page_refuses_equal_and_changed_input_before_publication() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
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
    let page = first_page_object(&store, &root);
    let digest = page.digest();
    let path = directory
        .path()
        .join("objects")
        .join(format!("{:02x}", digest[0]))
        .join(page.encode());
    let loan = quota.reserve_resources(1, 8192).unwrap();
    let mut encoded = std::fs::read(&path).unwrap();
    *encoded.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &encoded).unwrap();
    drop(encoded);
    drop(loan);
    let baseline = quota.used();
    let retained_count = retention.objects.lock().unwrap().len();

    for value in [0, 9] {
        let result = store.update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 0,
                bytes: vec![value; 4096],
            }],
            &retention,
            &parent,
            &mut || Ok(()),
        );
        assert!(
            matches!(result, Err(RamStoreError::Store(StoreError::Corrupt { id })) if id == page)
        );
        assert_eq!(retention.objects.lock().unwrap().len(), retained_count);
        assert_eq!(quota.used(), baseline);
        parent.check().unwrap();
    }
    drop(root);
    drop(scope);
    drop(parent);
    drop(store);
    assert_eq!(quota.used(), 0);
}

#[test]
fn each_existing_update_boundary_refuses_without_losing_original_custody() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let retention = Retention::default();
    let root = store
        .capture(
            topology(4 * 4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &parent,
            &mut || Ok(()),
        )
        .unwrap();
    let change = || RamPageChange {
        region_id: "main".into(),
        page_index: 1,
        bytes: vec![71; 4096],
    };
    let mut successful_polls = 0;
    let changed = store
        .update(&root, [change()], &retention, &parent, &mut || {
            successful_polls += 1;
            Ok(())
        })
        .unwrap();
    drop(changed);
    let baseline = quota.used();

    for refused_at in 1..=successful_polls {
        let mut polls = 0;
        let result = store.update(&root, [change()], &retention, &parent, &mut || {
            polls += 1;
            if polls == refused_at {
                Err(RamStoreError::Canceled)
            } else {
                Ok(())
            }
        });
        let error = result.unwrap_err();
        assert!(
            matches!(original_ram_failure(&error), RamStoreError::Canceled),
            "refused_at={refused_at} error={error:?}"
        );
        if let RamStoreError::Boundary(cause) = &error {
            assert!(matches!(
                cause.first_boundary(),
                Some(RamStoreError::Canceled)
            ));
            let RamStoreError::Store(StoreError::DirectoryScope { source }) =
                cause.storage_failure()
            else {
                panic!("actual directory refusal must remain owned: {error:?}")
            };
            assert!(source.cleanup_failure().is_none());
            assert_eq!(source.outcome().published_objects, 0);
            assert!(source.outcome().durable_objects <= 1);
            assert!(!source.outcome().durability_uncertain);
        }
        assert_eq!(polls, refused_at);
        drop(error);
        assert_eq!(quota.used(), baseline);
        parent.check().unwrap();
        assert_eq!(
            store
                .read_page(&root, "main", 1, &parent, &mut || Ok(()))
                .unwrap(),
            vec![1; 4096]
        );
    }
    // crucible-lint: allow direct-diagnostic -- the same component runs against frozen former and candidate source to compare bounded callback counts, without timing or native qualification.
    eprintln!("hash_reuse_update_boundary_count={successful_polls}");
    drop(root);
    drop(scope);
    drop(parent);
    drop(store);
    assert_eq!(quota.used(), 0);
}
