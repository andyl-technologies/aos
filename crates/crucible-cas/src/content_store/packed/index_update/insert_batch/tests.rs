//! Differential placement, real append-work and refusal custody controls.

use super::*;
use crate::content_store::packed::placement_tests::{Fixture, FixtureError, object, value};
use crate::content_store::packed::{
    checked_publication::Progress, index_build, index_format::Header, maintenance,
    placement_index::IndexSnapshot,
};
use std::os::unix::fs::FileExt;

fn seeded(fixture: &Fixture, count: u64) -> Result<IndexSnapshot, FixtureError> {
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut builder = index_build::Builder::new(Header::empty([41; 32]), &operation)?;
    for ordinal in 0..count {
        builder.push(
            &fixture.backend,
            Key::object(object(ordinal * 2)),
            value(ordinal * 2),
            &mut operation,
        )?;
    }
    let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
    terminal.cleanup?;
    let encoded = terminal.result?;
    fixture.backend.publish_index(&encoded)?;
    Ok(encoded.snapshot())
}

fn group(start: u64, stride: u64) -> [(ContentId, IndexEntry); wire::MAX_ROWS] {
    std::array::from_fn(|slot| {
        let ordinal = start + slot as u64 * stride;
        (
            object(ordinal),
            value(ordinal)
                .entry()
                .expect("valid placement fixture value"),
        )
    })
}

fn point_reference(
    update: &mut Update,
    fixture: &Fixture,
    entries: &[(ContentId, IndexEntry)],
    operation: &mut Operation<'_>,
) -> Result<(), StoreError> {
    for (id, entry) in entries {
        update.insert_absent(
            &fixture.backend,
            Key::object(*id),
            Value::object(*entry),
            operation,
        )?;
    }
    Ok(())
}

#[test]
fn batch_matches_point_membership_and_headers_through_inline_and_height_splits()
-> Result<(), FixtureError> {
    for count in [0, 1, 63, 64, 65, 4097] {
        let fixture = Fixture::new()?;
        let baseline = fixture.usage()?;
        {
            let snapshot = seeded(&fixture, count)?;
            let entries = group(1, if count > 65 { 128 } else { 2 });
            let mut operation = Operation {
                original: Some(&fixture.original),
                boundary: &mut || Ok(()),
            };
            let mut point = Update::new(&snapshot, &fixture.backend, &mut operation)?;
            point_reference(&mut point, &fixture, &entries, &mut operation)?;
            let mut batch = Update::new(&snapshot, &fixture.backend, &mut operation)?;
            batch.insert_absent_batch(&fixture.backend, &entries, &mut operation)?;
            let point_index = point.finish(&fixture.backend, &mut operation)?;
            let batch_index = batch.finish(&fixture.backend, &mut operation)?;
            assert_eq!(batch_index.header.count, point_index.header.count);
            assert_eq!(batch_index.header.records, point_index.header.records);
            assert_eq!(
                batch_index.header.logical_bytes,
                point_index.header.logical_bytes
            );
            assert_eq!(batch_index.header.generation, point_index.header.generation);
            for ordinal in 0..count {
                let key = Key::object(object(ordinal * 2));
                assert_eq!(
                    batch.find(key, &mut operation)?,
                    point.find(key, &mut operation)?
                );
            }
            for (id, entry) in entries {
                assert_eq!(
                    batch.find(Key::object(id), &mut operation)?,
                    Some(Value::object(entry))
                );
            }
            assert_eq!(
                batch.find(Key::object(object(u64::MAX - 1)), &mut operation)?,
                None
            );
        }
        assert_eq!(fixture.usage()?, baseline);
    }
    Ok(())
}

#[test]
fn production_group_appends_less_than_point_ancestor_versions() -> Result<(), FixtureError> {
    let entries = group(1, 128);
    let point_fixture = Fixture::new()?;
    let point_baseline = point_fixture.usage()?;
    let point_bytes = {
        let snapshot = seeded(&point_fixture, 4097)?;
        let mut operation = Operation {
            original: Some(&point_fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut update = Update::new(&snapshot, &point_fixture.backend, &mut operation)?;
        let before = update.arena.length();
        point_reference(&mut update, &point_fixture, &entries, &mut operation)?;
        let encoded = update.finish(&point_fixture.backend, &mut operation)?;
        assert_eq!(encoded.header.count, 4097 + 64);
        let growth = update
            .arena
            .length()
            .checked_sub(before)
            .expect("append-only reference");
        assert_eq!(
            update.arena.file()?.metadata()?.len(),
            update.arena.length()
        );
        growth
    };
    assert_eq!(point_fixture.usage()?, point_baseline);

    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4097)?;
        let before = snapshot.header.committed_bytes;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut progress = Progress::default();
        let encoded = maintenance::replacement(
            &fixture.backend,
            &snapshot,
            &entries,
            1 << 20,
            &mut operation,
            &mut progress,
        )?;
        assert_eq!(encoded.header.count, 4097 + 64);
        assert_eq!(encoded.header.packs, 1);
        assert_eq!(encoded.header.generation, 64);
        assert!(
            progress.obsolete_arenas.iter().all(Option::is_none),
            "same compaction predicate did not rebuild this prefix"
        );
        let growth = encoded
            .header
            .committed_bytes
            .checked_sub(before)
            .expect("same retained arena");
        assert!(
            growth < point_bytes,
            "actual group must avoid point ancestor appends: batch={growth} point={point_bytes}"
        );
        assert_eq!(progress.outcome.published_packs, 0);
        assert_eq!(progress.outcome.durable_objects, 0);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn duplicate_and_invalid_group_refuse_without_replacing_root() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 65)?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
        let before = update
            .finish(&fixture.backend, &mut operation)?
            .bytes()
            .to_vec();
        let duplicate = [(object(0), value(0).entry()?)];
        assert!(matches!(
            update.insert_absent_batch(&fixture.backend, &duplicate, &mut operation),
            Err(StoreError::InvalidComposition {
                reason: "Packed insertion requires confirmed absence"
            })
        ));
        assert!(!update.uncommitted_backing());
        assert_eq!(
            update.finish(&fixture.backend, &mut operation)?.bytes(),
            before
        );
        let repeated = [group(1, 2)[0]; 2];
        assert!(matches!(
            update.insert_absent_batch(&fixture.backend, &repeated, &mut operation),
            Err(StoreError::InvalidComposition { .. })
        ));
        assert!(matches!(
            update.insert_absent_batch(&fixture.backend, &[], &mut operation),
            Err(StoreError::Incompatible)
        ));
        let invalid = [(
            object(1),
            IndexEntry {
                offset: u64::MAX,
                ..group(1, 2)[0].1
            },
        )];
        assert!(matches!(
            update.insert_absent_batch(&fixture.backend, &invalid, &mut operation),
            Err(StoreError::Incompatible)
        ));
        assert_eq!(
            update.finish(&fixture.backend, &mut operation)?.bytes(),
            before
        );
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn corrupt_old_page_keeps_typed_refusal_and_closes_new_ledgers() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 65)?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
        let before = fixture.usage()?;
        let reference = match update.root {
            Root::Page(reference) => reference,
            Root::Inline(_) => panic!("real arena root"),
        };
        update.arena.file()?.write_all_at(&[0], reference.offset)?;
        let error = update
            .insert_absent_batch(&fixture.backend, &group(1, 2), &mut operation)
            .expect_err("authenticated old page refuses corruption");
        assert!(matches!(error, StoreError::Incompatible));
        assert!(!update.uncommitted_backing());
        assert_eq!(fixture.usage()?, before);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn original_refusal_precedes_ledger_birth_and_keeps_existing_physical_owner()
-> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = seeded(&fixture, 65)?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
    let before = update.arena.file()?.metadata()?.len();
    fixture.close_original();
    let error = update
        .insert_absent_batch(&fixture.backend, &group(1, 2), &mut operation)
        .expect_err("same original is closed");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert_eq!(update.arena.file()?.metadata()?.len(), before);
    assert!(!update.uncommitted_backing());
    Ok(())
}

#[test]
fn later_duplicate_retains_partial_arena_and_the_previous_root() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4097)?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
        let published_path = fixture
            .backend
            .admin
            .join(crate::content_store::packed::INDEX_FILE);
        let prior = std::fs::read(&published_path)?;
        let prior_header = update.header;
        let prior_root = match update.root {
            Root::Page(reference) => reference,
            Root::Inline(_) => panic!("real arena root"),
        };
        let before = update.arena.file()?.metadata()?.len();
        // The earlier absent key reaches a different leaf before the later
        // genuine duplicate. Its append is unreachable, not refunded backing.
        let entries = [
            (object(1), value(1).entry()?),
            (object(8192), value(8192).entry()?),
        ];
        let error = update
            .insert_absent_batch(&fixture.backend, &entries, &mut operation)
            .expect_err("later authenticated duplicate refuses the whole group");
        assert!(matches!(
            error,
            StoreError::InvalidComposition {
                reason: "Packed insertion requires confirmed absence"
            }
        ));
        assert!(update.uncommitted_backing());
        assert!(update.arena.file()?.metadata()?.len() > before);
        assert_eq!(update.header.count, prior_header.count);
        assert_eq!(update.header.records, prior_header.records);
        assert_eq!(update.header.generation, prior_header.generation);
        assert_eq!(update.header.logical_bytes, prior_header.logical_bytes);
        assert_eq!(update.header.committed_bytes, prior_header.committed_bytes);
        assert!(matches!(update.root, Root::Page(reference) if reference == prior_root));
        assert_eq!(std::fs::read(&published_path)?, prior);
        assert_eq!(update.find(Key::object(object(1)), &mut operation)?, None);
        assert_eq!(
            update.find(Key::object(object(8192)), &mut operation)?,
            Some(value(8192))
        );
        drop(error);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn original_post_write_refusal_keeps_typed_error_and_uncommitted_physical_tail()
-> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = seeded(&fixture, 65)?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
    let prior_header = update.header;
    let prior_root = match update.root {
        Root::Page(reference) => reference,
        Root::Inline(_) => panic!("real arena root"),
    };
    let before = update.arena.file()?.metadata()?.len();
    let name = crate::content_store::packed::index_io::arena_name(
        snapshot.header.arena.expect("seeded tree owns its arena"),
    );
    // This path observation belongs to the external test harness; it neither
    // issues descriptors nor replaces the operation's actual retained file.
    let path = fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).expect("hex arena name"));
    let mut observed_append = false;
    let mut revoke_after_write = || {
        let length = std::fs::metadata(&path)
            .map_err(|source| StoreError::StreamIo {
                operation: "observe-component-arena-tail",
                source,
            })?
            .len();
        if length > before {
            observed_append = true;
            fixture.close_original();
        }
        Ok(())
    };
    let error = update
        .insert_absent_batch(
            &fixture.backend,
            &group(1, 2),
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut revoke_after_write,
            },
        )
        .expect_err("same original refuses after an actual append");
    assert!(observed_append);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert!(update.uncommitted_backing());
    assert_eq!(update.header.count, prior_header.count);
    assert_eq!(update.header.generation, prior_header.generation);
    assert!(matches!(update.root, Root::Page(reference) if reference == prior_root));
    assert!(update.arena.file()?.metadata()?.len() > before);
    // The initiating error and physical owner remain live together. This
    // closed-account control does not claim permission to refund disk bytes.
    drop(error);
    drop(update);
    Ok(())
}

#[test]
fn unordered_private_group_refuses_before_page_io() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4097)?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut update = Update::new(&snapshot, &fixture.backend, &mut operation)?;
        let prior = update
            .finish(&fixture.backend, &mut operation)?
            .bytes()
            .to_vec();
        let before = update.arena.file()?.metadata()?.len();
        let mut rows = group(1, 128);
        rows.reverse();
        let mut cuts = 0;
        let error = update
            .insert_absent_batch(
                &fixture.backend,
                &rows,
                &mut Operation {
                    original: Some(&fixture.original),
                    boundary: &mut || {
                        cuts += 1;
                        Ok(())
                    },
                },
            )
            .expect_err("unordered private input must fail before native page work");
        assert!(matches!(error, StoreError::Incompatible));
        assert_eq!(
            cuts, 2,
            "only the admitted local ledger's pre/post cuts ran"
        );
        assert!(!update.uncommitted_backing());
        assert_eq!(update.arena.file()?.metadata()?.len(), before);
        assert_eq!(
            update.finish(&fixture.backend, &mut operation)?.bytes(),
            prior
        );
        drop(error);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}
