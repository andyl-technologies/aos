//! Whole-group membership, balanced-page, bound and actual refusal controls.
//!
//! The window reference is test-only. Production validates the complete group
//! before its page effects and never publishes an intermediate placement root.

use super::*;
use crate::content_store::packed::{PackId, maintenance::AppendBound};

fn inputs(count: usize, start: u64, stride: u64) -> Vec<(ContentId, IndexEntry)> {
    (0..count)
        .map(|slot| {
            let ordinal = start + slot as u64 * stride;
            (
                object(ordinal),
                value(ordinal).entry().expect("fixture entry"),
            )
        })
        .collect()
}

fn window_reference(
    update: &mut Update,
    fixture: &Fixture,
    entries: &[(ContentId, IndexEntry)],
    operation: &mut Operation<'_>,
) -> Result<(), StoreError> {
    for window in entries.chunks(wire::MAX_ROWS) {
        update.insert_absent_batch(&fixture.backend, window, operation)?;
    }
    Ok(())
}

#[test]
fn whole_groups_match_window_and_point_membership_across_supported_widths()
-> Result<(), FixtureError> {
    for count in [65, 127, 128, 129, 255, 256] {
        for old_count in [0, 1, 64, 65, 4097] {
            let fixture = Fixture::new()?;
            let baseline = fixture.usage()?;
            {
                let snapshot = seeded(&fixture, old_count)?;
                let before = std::fs::read(
                    fixture
                        .backend
                        .admin
                        .join(crate::content_store::packed::INDEX_FILE),
                )?;
                let entries = inputs(count, 1, if old_count > 65 { 128 } else { 2 });
                let mut operation = Operation {
                    original: Some(&fixture.original),
                    boundary: &mut || Ok(()),
                };
                let mut whole = Update::new(&snapshot, &fixture.backend, &mut operation)?;
                whole.insert_absent_batch(&fixture.backend, &entries, &mut operation)?;
                // Each subsequent owner opens the actual current tail; they
                // must not independently append over the same saved offset.
                let mut windows = Update::new(&snapshot, &fixture.backend, &mut operation)?;
                window_reference(&mut windows, &fixture, &entries, &mut operation)?;
                let mut points = Update::new(&snapshot, &fixture.backend, &mut operation)?;
                point_reference(&mut points, &fixture, &entries, &mut operation)?;
                let results = [
                    whole.finish(&fixture.backend, &mut operation)?,
                    windows.finish(&fixture.backend, &mut operation)?,
                    points.finish(&fixture.backend, &mut operation)?,
                ];
                for encoded in &results {
                    assert_eq!(encoded.header.count, old_count + count as u64);
                    assert_eq!(encoded.header.logical_bytes, old_count + count as u64);
                    assert_eq!(encoded.header.records, old_count + count as u64);
                    assert_eq!(
                        encoded.header.generation,
                        snapshot.header.generation + count as u64
                    );
                }
                for encoded in results {
                    let snapshot = encoded.snapshot();
                    let reader = snapshot.reader(&fixture.backend, &mut operation)?;
                    for (id, entry) in &entries {
                        assert_eq!(
                            reader.find(Key::object(*id), &mut operation)?,
                            Some(Value::object(*entry))
                        );
                    }
                    for ordinal in 0..old_count {
                        assert_eq!(
                            reader.find(Key::object(object(ordinal * 2)), &mut operation)?,
                            Some(value(ordinal * 2))
                        );
                    }
                }
                assert_eq!(
                    std::fs::read(
                        fixture
                            .backend
                            .admin
                            .join(crate::content_store::packed::INDEX_FILE,)
                    )?,
                    before
                );
            }
            assert_eq!(fixture.usage()?, baseline);
        }
    }
    Ok(())
}

#[test]
fn concentrated_full_group_emits_five_unchanged_width_leaf_pages() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = seeded(&fixture, 64)?;
    let entries = inputs(256, 1, 2);
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
    update.insert_absent_batch(&fixture.backend, &entries, &mut operation)?;
    let Root::Page(reference) = update.root else {
        panic!("five leaves require a physical branch root");
    };
    let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
    let node = update.load(
        reference,
        true,
        false,
        None,
        None,
        &mut bytes,
        &mut operation,
    )?;
    assert_eq!(node.height, 1);
    assert_eq!(node.count, 5);
    assert_eq!(node.records, 320);
    let children = (0..node.count)
        .map(|slot| node.child(slot))
        .collect::<Result<Vec<_>, _>>()?;
    for child in children {
        let leaf = update.load(child, false, false, None, None, &mut bytes, &mut operation)?;
        assert_eq!(leaf.height, 0);
        assert_eq!(leaf.count, 64);
        assert!(leaf.encoded_bytes().len() <= wire::PAGE_BYTES);
    }
    assert_eq!(MAX_REPLACEMENT_PAGES, 5);
    Ok(())
}

#[test]
fn actual_whole_group_append_and_pack_update_fit_checked_bound() -> Result<(), FixtureError> {
    for count in [65, 127, 128, 129, 255, 256] {
        for old_count in [0, 64, 65, 4097] {
            let fixture = Fixture::new()?;
            let snapshot = seeded(&fixture, old_count)?;
            let bound = AppendBound::batch(snapshot.header.height, count as u64)?.bytes()?;
            let mut operation = Operation {
                original: Some(&fixture.original),
                boundary: &mut || Ok(()),
            };
            let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
            let before = update.arena.length();
            update.insert_absent_batch(
                &fixture.backend,
                &inputs(count, 1, if old_count > 65 { 128 } else { 2 }),
                &mut operation,
            )?;
            update.set(
                &fixture.backend,
                Key::pack(PackId([8; 32])),
                Some(Value::pack(wire::PackRecord {
                    physical_bytes: 1 << 20,
                    objects: count as u64,
                    logical_bytes: count as u64,
                })),
                &mut operation,
            )?;
            update.finish(&fixture.backend, &mut operation)?;
            assert!(
                update.arena.length() - before <= bound,
                "old={old_count}, incoming={count}, bound={bound}"
            );
        }
    }
    Ok(())
}

#[test]
fn whole_group_overflow_precedes_corrupt_page_and_writes_no_tail() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let mut snapshot = seeded(&fixture, 4097)?;
        snapshot.header.generation = u64::MAX - wire::MAX_ROWS as u64;
        let reference = PageReference::decode(snapshot.body())?;
        let name = crate::content_store::packed::index_io::arena_name(
            snapshot.header.arena.expect("seeded tree owns an arena"),
        );
        let path = fixture
            .backend
            .admin
            .join(std::str::from_utf8(&name).expect("hex name"));
        let physical_before = std::fs::metadata(&path)?.len();
        let published = fixture
            .backend
            .admin
            .join(crate::content_store::packed::INDEX_FILE);
        let root_before = std::fs::read(&published)?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .write_all_at(&[0], reference.offset)?;

        let mut progress = Progress::default();
        let result = maintenance::replacement(
            &fixture.backend,
            &snapshot,
            &inputs(65, 1, 2),
            1 << 20,
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut || Ok(()),
            },
            &mut progress,
        );

        assert!(matches!(result, Err(StoreError::Quota)));
        assert!(!progress.outcome.index_reclamation_pending);
        assert_eq!(std::fs::metadata(&path)?.len(), physical_before);
        assert_eq!(std::fs::read(&published)?, root_before);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn denied_actual_control_admission_precedes_future_group_overflow() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let mut snapshot = seeded(&fixture, 4097)?;
    snapshot.header.generation = u64::MAX - wire::MAX_ROWS as u64;
    let published = fixture
        .backend
        .admin
        .join(crate::content_store::packed::INDEX_FILE);
    let root_before = std::fs::read(&published)?;
    fixture.close_original();
    let mut progress = Progress::default();
    let error = maintenance::replacement(
        &fixture.backend,
        &snapshot,
        &inputs(65, 1, 2),
        1 << 20,
        &mut Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        },
        &mut progress,
    )
    .err()
    .expect("actual original admission refuses");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(!progress.outcome.index_reclamation_pending);
    assert_eq!(std::fs::read(&published)?, root_before);
    drop(error);
    Ok(())
}

#[test]
fn wide_partial_append_refusal_retains_exact_old_root_and_physical_debt() -> Result<(), FixtureError>
{
    let fixture = Fixture::new()?;
    let snapshot = seeded(&fixture, 4097)?;
    let entries = inputs(256, 1, 2);
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
    let old_header = update.header;
    let Root::Page(old_root) = update.root else {
        panic!("seeded physical root")
    };
    let before = update.arena.length();
    let name = crate::content_store::packed::index_io::arena_name(
        snapshot.header.arena.expect("seeded physical arena"),
    );
    let path = fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).expect("hex name"));
    let mut observed_append = false;
    let mut revoke = || {
        if std::fs::metadata(&path)
            .map_err(|source| StoreError::StreamIo {
                operation: "observe-component-wide-tail",
                source,
            })?
            .len()
            > before
        {
            observed_append = true;
            fixture.close_original();
        }
        Ok(())
    };
    let error = update
        .insert_absent_batch(
            &fixture.backend,
            &entries,
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut revoke,
            },
        )
        .expect_err("actual post-append refusal");
    assert!(observed_append);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(update.uncommitted_backing());
    assert_eq!(update.header.count, old_header.count);
    assert_eq!(update.header.generation, old_header.generation);
    assert!(matches!(update.root, Root::Page(reference) if reference == old_root));
    let tail = std::fs::metadata(&path)?.len() - before;
    assert!(tail > 0);
    assert!(tail <= AppendBound::batch(old_header.height, entries.len() as u64)?.bytes()?);
    drop(error);
    drop(update);
    Ok(())
}

#[test]
fn every_supported_output_partition_preserves_disk_occupancy() -> Result<(), StoreError> {
    for count in 1..=wire::MAX_ROWS + batch::MAX_PUBLICATION_OBJECTS {
        let pages = output_pages(count)?;
        let mut end = 0;
        for page in 0..pages {
            let (start, next) = output_range(count, pages, page)?;
            assert_eq!(start, end);
            assert!(next - start <= wire::MAX_ROWS);
            assert!(pages == 1 || next - start >= wire::MIN_ROWS);
            end = next;
        }
        assert_eq!(end, count);
        assert!(pages <= MAX_REPLACEMENT_PAGES);
    }
    assert!(matches!(output_pages(321), Err(StoreError::Quota)));
    Ok(())
}

#[test]
fn wide_child_appends_do_not_mask_fresh_parent_corruption() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4097)?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
        let Root::Page(old_root) = update.root else {
            panic!("real parent page")
        };
        let before = update.arena.length();
        let name = crate::content_store::packed::index_io::arena_name(
            snapshot.header.arena.expect("real arena"),
        );
        let path = fixture
            .backend
            .admin
            .join(std::str::from_utf8(&name).expect("hex name"));
        let external = std::fs::OpenOptions::new().write(true).open(&path)?;
        let published = fixture
            .backend
            .admin
            .join(crate::content_store::packed::INDEX_FILE);
        let root_before = std::fs::read(&published)?;
        let mut changed = false;
        let mut mutate_after_child = || {
            if !changed
                && std::fs::metadata(&path)
                    .map_err(|source| StoreError::StreamIo {
                        operation: "observe-component-child-append",
                        source,
                    })?
                    .len()
                    > before
            {
                external
                    .write_all_at(&[0], old_root.offset)
                    .map_err(|source| StoreError::StreamIo {
                        operation: "mutate-component-old-parent",
                        source,
                    })?;
                changed = true;
            }
            Ok(())
        };
        let result = update.insert_absent_batch(
            &fixture.backend,
            &inputs(256, 1, 2),
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut mutate_after_child,
            },
        );
        assert!(changed);
        assert!(matches!(result, Err(StoreError::Incompatible)));
        assert!(update.uncommitted_backing());
        assert_eq!(update.header.count, snapshot.header.count);
        assert!(matches!(update.root, Root::Page(reference) if reference == old_root));
        assert_eq!(std::fs::read(&published)?, root_before);
        assert!(std::fs::metadata(&path)?.len() > before);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}
