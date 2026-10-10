//! Real placement growth, failed-tail, authentication and original controls.
//!
//! The existing placement fixture retains its eight-descriptor/four-MiB bank.
//! Directly constructed failed tails model unreachable arena backing; they do
//! not certify mounted quota enforcement or whole-process resource purposes.

use super::*;
use crate::content_store::packed::index_io::Operation;
use crate::content_store::packed::placement_tests::{Fixture, FixtureError, object, value};
use crate::content_store::packed::{
    INDEX_FILE, IndexEntry, PackId, checked_publication, index_build, index_format::Header,
    index_io, index_update, maintenance, placement_index::IndexSnapshot,
};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

const PACK_BYTES: u64 = 1 << 20;

fn seeded(fixture: &Fixture, count: u64) -> Result<IndexSnapshot, FixtureError> {
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut builder = index_build::Builder::new(Header::empty([49; 32]), &operation)?;
    for ordinal in 0..count {
        builder.push(
            &fixture.backend,
            wire::Key::object(object(ordinal * 2)),
            value(ordinal * 2),
            &mut operation,
        )?;
    }
    if count != 0 {
        builder.push(
            &fixture.backend,
            wire::Key::pack(PackId([7; 32])),
            wire::Value::pack(wire::PackRecord {
                physical_bytes: PACK_BYTES,
                objects: count,
                logical_bytes: count,
            }),
            &mut operation,
        )?;
    }
    let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
    terminal.cleanup?;
    let encoded = terminal.result?;
    fixture.backend.publish_index(&encoded)?;
    Ok(encoded.snapshot())
}

fn entries() -> [(crate::content_store::ContentId, IndexEntry); wire::MAX_ROWS] {
    std::array::from_fn(|slot| {
        (
            object(1 + slot as u64 * 128),
            IndexEntry {
                pack: PackId([8; 32]),
                offset: slot as u64,
                length: 1,
            },
        )
    })
}

fn arena_path(fixture: &Fixture, snapshot: &IndexSnapshot) -> PathBuf {
    let identity = snapshot
        .header
        .arena
        .expect("seeded large index has an arena");
    let name = index_io::arena_name(identity);
    fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).expect("fixed arena filename contains ASCII"))
}

#[test]
fn batch_bound_includes_the_raised_height_pack_record_update() -> Result<(), FixtureError> {
    let mut raised_height_before_pack = false;
    for (count, objects) in [
        (0, 1),
        (63, 1),
        (64, 1),
        (0, 64),
        (1, 64),
        (62, 64),
        (63, 64),
        (64, 64),
        (65, 64),
        (4096, 64),
    ] {
        let object_count = objects as u64;
        let fixture = Fixture::new()?;
        let baseline = fixture.usage()?;
        {
            let snapshot = seeded(&fixture, count)?;
            let append = AppendBound::batch(snapshot.header.height, object_count)?;
            let before = snapshot.header.committed_bytes;
            let mut operation = Operation {
                original: Some(&fixture.original),
                boundary: &mut || Ok(()),
            };
            // Replacement may legitimately compact a small arena because its
            // append allowance exceeds the retained-tail threshold. Measure
            // the actual append primitives independently of that policy.
            let mut update =
                index_update::Update::new(&snapshot, &fixture.backend, &mut operation)?;
            update.insert_absent_batch(&fixture.backend, &entries()[..objects], &mut operation)?;
            let batch = update.finish(&fixture.backend, &mut operation)?;
            raised_height_before_pack |= batch.header.height > snapshot.header.height;
            drop(batch);

            let prior = update.set(
                &fixture.backend,
                wire::Key::pack(PackId([8; 32])),
                Some(wire::Value::pack(wire::PackRecord {
                    physical_bytes: PACK_BYTES,
                    objects: object_count,
                    logical_bytes: object_count,
                })),
                &mut operation,
            )?;
            assert!(prior.is_none(), "count={count}, objects={objects}");
            let encoded = update.finish(&fixture.backend, &mut operation)?;

            assert_eq!(
                encoded.header.count,
                count + object_count,
                "count={count}, objects={objects}"
            );
            assert_eq!(
                encoded.header.packs,
                u64::from(count != 0) + 1,
                "count={count}, objects={objects}"
            );
            assert_eq!(
                encoded.header.records,
                snapshot.header.records + object_count + 1,
                "count={count}, objects={objects}"
            );
            assert!(
                encoded.header.height <= snapshot.header.height + 2,
                "count={count}, objects={objects}"
            );
            if let Some(identity) = snapshot.header.arena {
                assert_eq!(
                    encoded.header.arena,
                    Some(identity),
                    "count={count}, objects={objects}"
                );
            }
            let growth = encoded
                .header
                .committed_bytes
                .checked_sub(before)
                .expect("unchanged arena retains its append-only tail");
            assert!(
                growth <= append.bytes()?,
                "count={count}, objects={objects}: pack-record growth is included: {growth}"
            );
            let replacement = encoded.snapshot();
            if replacement.header.arena.is_some() {
                assert_eq!(
                    fs::metadata(arena_path(&fixture, &replacement))?.len(),
                    replacement.header.committed_bytes,
                    "count={count}, objects={objects}"
                );
            }
            let reader = replacement.reader(&fixture.backend, &mut operation)?;
            let pack = reader
                .find(wire::Key::pack(PackId([8; 32])), &mut operation)?
                .expect("the real subsequent pack-record mutation completed")
                .pack_record()?;
            assert_eq!(
                pack.objects, object_count,
                "count={count}, objects={objects}"
            );
            assert_eq!(
                pack.logical_bytes, object_count,
                "count={count}, objects={objects}"
            );
            assert_eq!(
                pack.physical_bytes, PACK_BYTES,
                "count={count}, objects={objects}"
            );
        }
        assert_eq!(
            fixture.usage()?,
            baseline,
            "count={count}, objects={objects}"
        );
    }
    assert!(
        raised_height_before_pack,
        "a batch must raise the height before the pack update"
    );
    Ok(())
}

#[test]
fn actual_batch_bound_keeps_a_tail_that_the_point_estimate_would_rebuild()
-> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4096)?;
        let append = AppendBound::batch(snapshot.header.height, 64)?;
        let old = AppendBound::point(snapshot.header.height, 65)?;
        assert!(append.bytes()? < old.bytes()?);
        let reachable = (snapshot.header.records + 65).div_ceil(16) * 2 + 1;
        let ceiling = reachable * wire::PAGE_BYTES as u64 * 2;
        let retained_tail = ceiling - append.bytes()?;
        assert!(retained_tail >= snapshot.header.committed_bytes);
        assert!(retained_tail + old.bytes()? > ceiling);
        let path = arena_path(&fixture, &snapshot);
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(retained_tail)?;
        let root_before = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let mut progress = checked_publication::Progress::default();
        let encoded = maintenance::replacement(
            &fixture.backend,
            &snapshot,
            &entries(),
            PACK_BYTES,
            &mut operation,
            &mut progress,
        )?;
        assert_eq!(
            encoded.header.arena, snapshot.header.arena,
            "one real batch must use its own append bound"
        );
        assert!(progress.obsolete_arenas.iter().all(Option::is_none));
        assert!(progress.outcome.index_reclamation_pending);
        let growth = encoded.header.committed_bytes - retained_tail;
        assert!(growth <= append.bytes()?);
        assert_eq!(fs::metadata(&path)?.len(), encoded.header.committed_bytes);
        assert_eq!(
            fs::read(fixture.backend.admin.join(INDEX_FILE))?,
            root_before
        );
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn bound_cannot_make_a_corrupt_parent_eligible() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4096)?;
        let reference = wire::PageReference::decode(snapshot.body())?;
        let path = arena_path(&fixture, &snapshot);
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .write_all_at(&[0], reference.offset)?;
        let root_before = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
        let physical_before = fs::metadata(&path)?.len();
        let mut progress = checked_publication::Progress::default();
        let result = maintenance::replacement(
            &fixture.backend,
            &snapshot,
            &entries(),
            PACK_BYTES,
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut || Ok(()),
            },
            &mut progress,
        );
        assert!(matches!(&result, Err(StoreError::Incompatible)));
        drop(result);
        assert_eq!(fs::metadata(&path)?.len(), physical_before);
        assert_eq!(
            fs::read(fixture.backend.admin.join(INDEX_FILE))?,
            root_before
        );
        assert!(!progress.outcome.index_reclamation_pending);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn bound_does_not_replace_actual_page_admission() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4096)?;
        let path = arena_path(&fixture, &snapshot);
        let physical_before = fs::metadata(&path)?.len();
        let root_before = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
        fixture.refuse_page_reservations();
        let mut progress = checked_publication::Progress::default();
        let result = maintenance::replacement(
            &fixture.backend,
            &snapshot,
            &entries(),
            PACK_BYTES,
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut || Ok(()),
            },
            &mut progress,
        );
        let cause = match &result {
            Err(StoreError::DecodeAdmission { source, .. }) => source,
            Err(error) => panic!("retain the typed original page refusal: {error:?}"),
            Ok(_) => panic!("the original page debit must refuse"),
        };
        assert!(matches!(
            std::error::Error::source(cause).and_then(|cause| cause.downcast_ref::<StoreError>()),
            Some(StoreError::Quota)
        ));
        drop(result);
        assert_eq!(fs::metadata(&path)?.len(), physical_before);
        assert_eq!(
            fs::read(fixture.backend.admin.join(INDEX_FILE))?,
            root_before
        );
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn first_original_refusal_retains_the_actual_uncommitted_tail() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = seeded(&fixture, 4096)?;
        let path = arena_path(&fixture, &snapshot);
        let before = fs::metadata(&path)?.len();
        let root_before = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
        let mut cuts = 0;
        let mut boundary = || {
            cuts += 1;
            if fs::metadata(&path)
                .map_err(|source| StoreError::StreamIo {
                    operation: "test-observe-retained-tail",
                    source,
                })?
                .len()
                > before
            {
                return Err(StoreError::Unauthorized);
            }
            Ok(())
        };
        let mut progress = checked_publication::Progress::default();
        let result = maintenance::replacement(
            &fixture.backend,
            &snapshot,
            &entries(),
            PACK_BYTES,
            &mut Operation {
                original: Some(&fixture.original),
                boundary: &mut boundary,
            },
            &mut progress,
        );
        assert!(matches!(&result, Err(StoreError::Unauthorized)));
        drop(result);
        assert!(cuts > 0);
        assert!(progress.outcome.index_reclamation_pending);
        assert!(fs::metadata(&path)?.len() > before);
        assert_eq!(
            fs::read(fixture.backend.admin.join(INDEX_FILE))?,
            root_before
        );
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn point_geometry_and_invalid_private_inputs_keep_their_existing_bound() -> Result<(), StoreError> {
    for height in 0..wire::MAX_HEIGHT as u8 {
        for changes in [1, 2, 65] {
            assert_eq!(
                AppendBound::point(height, changes)?.pages,
                (4 * (u64::from(height) + 1) + 2) * changes
            );
        }
        for objects in 1..=wire::MAX_ROWS as u64 {
            let batch = AppendBound::batch(height, objects)?;
            let legacy = AppendBound::point(height, objects + 1)?;
            assert!(batch.pages <= legacy.pages);
        }
        for objects in [0, 65, u64::MAX - 1] {
            let point = AppendBound::point(height, objects + 1);
            let batch = AppendBound::batch(height, objects);
            match (point, batch) {
                (Ok(point), Ok(batch)) => assert_eq!(point.pages, batch.pages),
                (Err(StoreError::Quota), Err(StoreError::Quota)) => {}
                _ => panic!("out-of-contract input retains old geometry/refusal"),
            }
        }
    }
    assert!(matches!(
        AppendBound::batch(0, u64::MAX),
        Err(StoreError::Quota)
    ));
    Ok(())
}
