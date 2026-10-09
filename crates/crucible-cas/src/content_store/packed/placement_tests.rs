//! Finite placement codec and copy-on-write component controls.
//!
//! The fixture directory and test runner are outside the component bank. Actual
//! placement paths, descriptors and buffers borrow one finite original account;
//! these tests do not certify pack bodies, namespace disk quotas or native heap.

use super::index_format::{self as wire, Key, Node, PageReference, Value};
use super::index_io::Operation;
use super::index_update::Update;
use super::placement_index::{EncodedIndex, IndexSnapshot};
use super::*;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, ResourceLoan};
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicBool;
use tempfile::TempDir;

const RESIDENT_BYTES: u64 = 4 * 1024 * 1024;
const DESCRIPTORS: u64 = 8;

struct Quota {
    resources: FixtureResourceBudget,
    closed: AtomicBool,
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT_BYTES)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        self.resources.reserve(descriptors, bytes)
    }
}

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeAdmissionError),
}

struct Fixture {
    _directory: TempDir,
    backend: PackedBlobBackend,
    quota: Arc<Quota>,
    original: DecodeBudget,
}

impl Fixture {
    fn new() -> Result<Self, FixtureError> {
        let directory = TempDir::new()?;
        let backend = PackedBlobBackend::open(
            "placement-component",
            directory.path(),
            MIN_TARGET_PACK_BYTES,
        )?;
        let quota = Arc::new(Quota {
            resources: FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES),
            closed: AtomicBool::new(false),
        });
        let original = DecodeBudget::for_store(quota.clone())?;
        Ok(Self {
            _directory: directory,
            backend,
            quota,
            original,
        })
    }
}

fn object(ordinal: u64) -> ContentId {
    let mut digest = [0; 32];
    digest[24..].copy_from_slice(&ordinal.to_be_bytes());
    ContentId {
        kind: ObjectKind::RamExtent,
        schema_version: 1,
        digest,
    }
}

fn value(ordinal: u64) -> Value {
    Value::object(IndexEntry {
        pack: PackId([7; 32]),
        offset: ordinal,
        length: 1,
    })
}

fn published_two_leaf_index(fixture: &Fixture) -> Result<IndexSnapshot, FixtureError> {
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    let initial = EncodedIndex::empty_under(&fixture.backend, [21; 32], &mut operation)?.snapshot();
    let mut update = Update::new(&initial, &fixture.backend, &mut operation)?;
    for ordinal in 0..65 {
        update.set(
            &fixture.backend,
            Key::object(object(ordinal)),
            Some(value(ordinal)),
            &mut operation,
        )?;
    }
    let encoded = update.finish(&fixture.backend, &mut operation)?;
    // Fixture publication establishes real root bytes before the selected
    // checked reads; it does not donate checked publication capability.
    fixture.backend.publish_index(&encoded)?;
    Ok(encoded.snapshot())
}

#[test]
fn placement_same_reader_rechecks_changed_page_checksum_and_reference() -> Result<(), FixtureError>
{
    let fixture = Fixture::new()?;
    let baseline = fixture.quota.resources.usage()?;
    {
        let snapshot = published_two_leaf_index(&fixture)?;
        let root_before = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
        let mut boundary = || Ok(());
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut boundary,
        };
        let reader = snapshot.reader(&fixture.backend, &mut operation)?;
        assert_eq!(
            reader.find(Key::object(object(0)), &mut operation)?,
            Some(value(0))
        );

        let arena = snapshot.header.arena.expect("two-leaf tree has an arena");
        let name = index_io::arena_name(arena);
        let path = fixture
            .backend
            .admin
            .join(std::str::from_utf8(&name).unwrap());
        let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
        let reference = PageReference::decode(snapshot.body())?;
        let mut root_page = vec![0; reference.length as usize];
        file.read_exact_at(&mut root_page, reference.offset)?;
        let leaf = Node::parse(&root_page, true)?.child(0)?;
        let mut leaf_page = vec![0; leaf.length as usize];
        file.read_exact_at(&mut leaf_page, leaf.offset)?;
        let original_page = leaf_page.clone();
        let node = Node::parse(&leaf_page, false)?;
        let (count, records) = (node.count, node.records);

        // First damage the actual backing page without updating its checksum.
        leaf_page[wire::PAGE_HEADER_BYTES + wire::KEY_BYTES] ^= 1;
        file.write_all_at(&leaf_page, leaf.offset)?;
        assert!(matches!(
            reader.find(Key::object(object(0)), &mut operation),
            Err(StoreError::Incompatible)
        ));

        // A canonically checksummed replacement still lacks the parent's
        // authenticated digest. The same retained reader must reject it too.
        leaf_page.truncate(leaf_page.len() - 32);
        wire::finish_node(&mut leaf_page, count, records)?;
        Node::parse(&leaf_page, false)?;
        file.write_all_at(&leaf_page, leaf.offset)?;
        assert!(matches!(
            reader.find(Key::object(object(0)), &mut operation),
            Err(StoreError::Incompatible)
        ));

        file.write_all_at(&original_page, leaf.offset)?;
        assert_eq!(
            reader.find(Key::object(object(0)), &mut operation)?,
            Some(value(0))
        );
        assert_eq!(
            fs::read(fixture.backend.admin.join(INDEX_FILE))?,
            root_before
        );
    }
    assert_eq!(fixture.quota.resources.usage()?, baseline);
    Ok(())
}

#[test]
fn placement_read_cuts_keep_original_refusal_and_close_paid_buffers() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.quota.resources.usage()?;
    {
        let snapshot = published_two_leaf_index(&fixture)?;
        let root_before = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
        let mut healthy = || Ok(());
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut healthy,
        };
        let reader = snapshot.reader(&fixture.backend, &mut operation)?;
        let reader_usage = fixture.quota.resources.usage()?;

        // Callback one is the lookup entry. Two and three enclose the first
        // actual arena read. Owned bytes witness whether that read occurred.
        for cut in [2, 3] {
            let mut buffer = operation.buffer(wire::PAGE_BYTES)?;
            buffer.value.resize(wire::PAGE_BYTES, 0xa5);
            let mut seen = 0;
            let mut revoke = || {
                seen += 1;
                if seen == cut {
                    fixture.quota.closed.store(true, Ordering::SeqCst);
                }
                Ok(())
            };
            let error = reader
                .find_into(
                    Key::object(object(0)),
                    &mut buffer,
                    &mut Operation {
                        original: Some(&fixture.original),
                        boundary: &mut revoke,
                    },
                )
                .expect_err("original refusal must prevent a selected value");
            assert!(matches!(error.original_failure(), StoreError::Unauthorized));
            assert_eq!(seen, cut);
            if cut == 2 {
                assert_eq!(&buffer.value[..16], &[0xa5; 16]);
            } else {
                assert_eq!(&buffer.value[..16], b"CRUCPIDXPAGE0002");
            }
            drop(buffer);
            drop(error);
            fixture.quota.closed.store(false, Ordering::SeqCst);
            assert_eq!(fixture.quota.resources.usage()?, reader_usage);
            assert_eq!(
                fs::read(fixture.backend.admin.join(INDEX_FILE))?,
                root_before
            );
        }
        assert_eq!(
            reader.find(Key::object(object(0)), &mut operation)?,
            Some(value(0))
        );
    }
    assert_eq!(fixture.quota.resources.usage()?, baseline);
    Ok(())
}

#[test]
fn placement_split_cursor_merge_and_root_collapse_keep_one_original() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.quota.resources.usage()?;
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    {
        let initial =
            EncodedIndex::empty_under(&fixture.backend, [1; 32], &mut operation)?.snapshot();
        let mut update = Update::new(&initial, &fixture.backend, &mut operation)?;
        // Crossing 64 leaf rows and 64 root children exercises both split
        // levels. Ordinal digests provide a constant-space expected order.
        for ordinal in 0..4_100 {
            assert_eq!(
                update.set(
                    &fixture.backend,
                    Key::object(object(ordinal)),
                    Some(value(ordinal)),
                    &mut operation
                )?,
                None
            );
            let (_, resident) = fixture.quota.resources.usage()?;
            assert!(resident - baseline.1 <= 6 * wire::PAGE_BYTES as u64 + 65_536);
        }
        let grown = update.finish(&fixture.backend, &mut operation)?.snapshot();
        assert_eq!(grown.header.count, 4_100);
        assert!(grown.header.height >= 2);
        let reader = grown.reader(&fixture.backend, &mut operation)?;
        let mut cursor = reader.cursor(&mut operation)?;
        for ordinal in 0..4_100 {
            assert_eq!(
                cursor.next(&mut operation)?,
                Some((Key::object(object(ordinal)), value(ordinal)))
            );
            assert_eq!(
                reader.find(Key::object(object(ordinal)), &mut operation)?,
                Some(value(ordinal))
            );
        }
        assert_eq!(cursor.next(&mut operation)?, None);
        drop(cursor);
        drop(reader);

        let mut update = Update::new(&grown, &fixture.backend, &mut operation)?;
        for ordinal in (24..4_100).rev() {
            assert_eq!(
                update.set(
                    &fixture.backend,
                    Key::object(object(ordinal)),
                    None,
                    &mut operation
                )?,
                Some(value(ordinal))
            );
        }
        let small = update.finish(&fixture.backend, &mut operation)?.snapshot();
        assert_eq!(small.header.count, 24);
        assert_eq!(small.header.arena, None);
        let mut update = Update::new(&small, &fixture.backend, &mut operation)?;
        for ordinal in 0..24 {
            assert_eq!(
                update.set(
                    &fixture.backend,
                    Key::object(object(ordinal)),
                    None,
                    &mut operation
                )?,
                Some(value(ordinal))
            );
        }
        let empty = update.finish(&fixture.backend, &mut operation)?.snapshot();
        assert_eq!(empty.header.count, 0);
        assert_eq!(empty.header.arena, None);
        assert_eq!(Node::parse(empty.body(), true)?.count, 0);
    }
    assert_eq!(fixture.quota.resources.usage()?, baseline);
    Ok(())
}

#[test]
fn placement_full_key_distinguishes_schema_kind_and_pack_tags() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    let initial = EncodedIndex::empty_under(&fixture.backend, [2; 32], &mut operation)?.snapshot();
    let mut update = Update::new(&initial, &fixture.backend, &mut operation)?;
    let base = object(1);
    let schema = ContentId {
        schema_version: 2,
        ..base
    };
    let kind = ContentId {
        kind: ObjectKind::RamTree,
        ..base
    };
    for (id, ordinal) in [(base, 1), (schema, 2), (kind, 3)] {
        update.set(
            &fixture.backend,
            Key::object(id),
            Some(value(ordinal)),
            &mut operation,
        )?;
    }
    let pack = PackId([7; 32]);
    let record = wire::PackRecord {
        physical_bytes: 64,
        objects: 3,
        logical_bytes: 3,
    };
    update.set(
        &fixture.backend,
        Key::pack(pack),
        Some(Value::pack(record)),
        &mut operation,
    )?;
    let snapshot = update.finish(&fixture.backend, &mut operation)?.snapshot();
    let reader = snapshot.reader(&fixture.backend, &mut operation)?;
    for (id, ordinal) in [(base, 1), (schema, 2), (kind, 3)] {
        assert_eq!(
            reader.find(Key::object(id), &mut operation)?,
            Some(value(ordinal))
        );
    }
    assert_eq!(
        reader.find(Key::pack(pack), &mut operation)?,
        Some(Value::pack(record))
    );
    assert_eq!(snapshot.header.count, 3);
    assert_eq!(snapshot.header.packs, 1);
    assert_eq!(snapshot.header.records, 4);
    Ok(())
}

#[test]
fn placement_rejects_forward_child_ranges_and_old_root_version() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let mut boundary = || Ok(());
    let operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
    wire::begin_node(&mut bytes.value, 1);
    for ordinal in 0..2 {
        bytes
            .value
            .extend_from_slice(&Key::object(object(ordinal)).0);
        PageReference {
            offset: 100,
            length: 100,
            digest: [9; 32],
            records: 16,
            height: 0,
        }
        .append(&mut bytes.value);
    }
    wire::finish_node(&mut bytes.value, 2, 32)?;
    let node = Node::parse(&bytes.value, true)?;
    assert!(matches!(
        node.validate_children_before(100),
        Err(StoreError::Incompatible)
    ));

    let old = vec![0; wire::ROOT_HEADER_BYTES + wire::REFERENCE_BYTES + 32];
    assert!(matches!(
        wire::Header::decode(&old, fixture.backend.configuration),
        Err(StoreError::Unsupported {
            capability: "packed-index-version"
        })
    ));
    // Exact old empty-root grammar, retained as a rejection witness rather
    // than an importer or a second executable placement implementation.
    let mut existing_legacy = b"crucible.content-store.pack-index.v1\0".to_vec();
    existing_legacy.extend_from_slice(&fixture.backend.configuration);
    existing_legacy.extend_from_slice(&[0; 32 + 8 + 1 + 4 + 32]);
    assert!(matches!(
        wire::Header::decode(&existing_legacy, fixture.backend.configuration),
        Err(StoreError::Unsupported {
            capability: "packed-index-version"
        })
    ));
    Ok(())
}

#[test]
fn placement_original_callback_revocation_stops_before_arena_creation() -> Result<(), FixtureError>
{
    let fixture = Fixture::new()?;
    let mut healthy = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut healthy,
    };
    let initial = EncodedIndex::empty_under(&fixture.backend, [3; 32], &mut operation)?.snapshot();
    let mut update = Update::new(&initial, &fixture.backend, &mut operation)?;
    for ordinal in 0..64 {
        update.set(
            &fixture.backend,
            Key::object(object(ordinal)),
            Some(value(ordinal)),
            &mut operation,
        )?;
    }
    let before = fs::read_dir(&fixture.backend.admin)?.count();
    let mut calls = 0;
    let mut revoke = || {
        calls += 1;
        fixture.quota.closed.store(true, Ordering::SeqCst);
        Ok(())
    };
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut revoke,
    };
    let error = update
        .set(
            &fixture.backend,
            Key::object(object(64)),
            Some(value(64)),
            &mut operation,
        )
        .expect_err("revoked original must stop the arena transition");
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(calls, 1);
    assert_eq!(fs::read_dir(&fixture.backend.admin)?.count(), before);
    Ok(())
}

#[test]
fn placement_component_geometry_records_actual_native_sizes() {
    println!(
        "placement geometry: page={} header={} key={} value={} reference={} bytes_owner={} file_owner={} update={} reader={} cursor={} builder={} arena={} terminal={}",
        wire::PAGE_BYTES,
        std::mem::size_of::<wire::Header>(),
        std::mem::size_of::<Key>(),
        std::mem::size_of::<Value>(),
        std::mem::size_of::<PageReference>(),
        std::mem::size_of::<super::index_io::Bytes>(),
        std::mem::size_of::<super::index_io::IndexFile>(),
        std::mem::size_of::<Update>(),
        std::mem::size_of::<super::placement_index::Reader<'_>>(),
        std::mem::size_of::<super::placement_index::Cursor<'_, '_>>(),
        std::mem::size_of::<super::index_build::Builder>(),
        std::mem::size_of::<super::index_arena::Arena>(),
        std::mem::size_of::<super::index_build::Terminal>(),
    );
    assert_eq!(wire::KEY_BYTES + wire::VALUE_BYTES, wire::LEAF_ROW_BYTES);
    assert_eq!(
        wire::KEY_BYTES + wire::REFERENCE_BYTES,
        wire::BRANCH_ROW_BYTES
    );
    assert_eq!(2_u128 * 16_u128.pow(16), 1_u128 << 65);
}

#[test]
fn placement_sorted_builder_preserves_occupancy_at_tail_boundaries() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.quota.resources.usage()?;
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    for count in [0, 1, 16, 64, 65, 79, 80, 81, 4_096, 4_100, 10_000] {
        let mut builder =
            super::index_build::Builder::new(wire::Header::empty([4; 32]), &operation)?;
        for ordinal in 0..count {
            builder.push(
                &fixture.backend,
                Key::object(object(ordinal)),
                value(ordinal),
                &mut operation,
            )?;
            let (descriptors, resident) = fixture.quota.resources.usage()?;
            assert!(descriptors - baseline.0 <= 2);
            assert!(resident - baseline.1 <= 6 * wire::PAGE_BYTES as u64 + 65_536);
        }
        let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
        terminal.cleanup?;
        let snapshot = terminal.result?.snapshot();
        assert_eq!(snapshot.header.count, count);
        assert_eq!(snapshot.header.arena.is_none(), count <= 64);
        let reader = snapshot.reader(&fixture.backend, &mut operation)?;
        let mut cursor = reader.cursor(&mut operation)?;
        for ordinal in 0..count {
            assert_eq!(
                cursor.next(&mut operation)?,
                Some((Key::object(object(ordinal)), value(ordinal)))
            );
        }
        assert_eq!(cursor.next(&mut operation)?, None);
    }
    assert_eq!(fixture.quota.resources.usage()?, baseline);
    assert!(
        !fs::read_dir(&fixture.backend.admin)?.any(|entry| entry.is_ok_and(|entry| entry
            .file_name()
            .to_string_lossy()
            .starts_with(".index-build.tmp-")))
    );
    Ok(())
}

#[test]
fn placement_sorted_builder_rejects_damaged_native_scratch_before_root_seal()
-> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    let mut builder = super::index_build::Builder::new(wire::Header::empty([5; 32]), &operation)?;
    for ordinal in 0..80 {
        builder.push(
            &fixture.backend,
            Key::object(object(ordinal)),
            value(ordinal),
            &mut operation,
        )?;
    }
    let scratch = fs::read_dir(&fixture.backend.admin)?
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".index-build.tmp-")
        })
        .expect("eighty rows require a private branch scratch");
    let file = OpenOptions::new().write(true).open(scratch.path())?;
    file.write_all_at(&[0xff], 0)?;
    drop(file);
    let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
    assert!(matches!(terminal.result, Err(StoreError::Incompatible)));
    terminal.cleanup?;
    assert!(terminal.uncommitted_arena_created);
    assert!(!scratch.path().exists());
    Ok(())
}

#[test]
fn placement_sorted_builder_retains_work_and_distinct_cleanup_failure() -> Result<(), FixtureError>
{
    let fixture = Fixture::new()?;
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    let mut builder = super::index_build::Builder::new(wire::Header::empty([6; 32]), &operation)?;
    for ordinal in 0..80 {
        builder.push(
            &fixture.backend,
            Key::object(object(ordinal)),
            value(ordinal),
            &mut operation,
        )?;
    }
    let scratch = fs::read_dir(&fixture.backend.admin)?
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".index-build.tmp-")
        })
        .expect("eighty rows require a private branch scratch");
    fs::remove_file(scratch.path())?;
    fs::create_dir(scratch.path())?;
    let terminal = builder.terminate(
        &fixture.backend,
        &mut operation,
        Err(StoreError::Unauthorized),
    );
    assert!(matches!(terminal.result, Err(StoreError::Unauthorized)));
    assert!(
        matches!(terminal.cleanup, Err(StoreError::StreamIo { source, .. }) if source.kind() == io::ErrorKind::IsADirectory)
    );
    assert!(terminal.uncommitted_arena_created);
    fs::remove_dir(scratch.path())?;
    Ok(())
}

#[test]
fn placement_compaction_keeps_old_root_until_durable_replacement() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.quota.resources.usage()?;
    let mut boundary = || Ok(());
    let index = {
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut boundary,
        };
        let mut builder =
            super::index_build::Builder::new(wire::Header::empty([11; 32]), &operation)?;
        for ordinal in 0..4_096 {
            builder.push(
                &fixture.backend,
                Key::object(object(ordinal)),
                value(ordinal),
                &mut operation,
            )?;
        }
        builder.push(
            &fixture.backend,
            Key::pack(PackId([7; 32])),
            Value::pack(wire::PackRecord {
                physical_bytes: 8_192,
                objects: 4_096,
                logical_bytes: 4_096,
            }),
            &mut operation,
        )?;
        let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
        terminal.cleanup?;
        let encoded = terminal.result?;
        fixture.backend.publish_index(&encoded)?;
        encoded.snapshot()
    };
    let identity = index.header.arena.expect("large tree has an arena");
    let name = index_io::arena_name(identity);
    let old_path = fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).unwrap());
    let old_bytes = fs::read(fixture.backend.admin.join(INDEX_FILE))?;
    let (old_reader, replacement, mut progress) = {
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut boundary,
        };
        let old_reader = index.reader(&fixture.backend, &mut operation)?;
        // A failed append can leave an arbitrarily longer physical tail while the
        // committed authenticated coordinates remain unchanged.
        OpenOptions::new()
            .write(true)
            .open(&old_path)?
            .set_len(16 * 1024 * 1024)?;
        let mut progress = checked_publication::Progress::default();
        let id = object(4_096);
        let replacement = maintenance::replacement(
            &fixture.backend,
            &index,
            &[(
                id,
                IndexEntry {
                    pack: PackId([7; 32]),
                    offset: 4_096,
                    length: 1,
                },
            )],
            8_192,
            &mut operation,
            &mut progress,
        )?;
        assert_ne!(replacement.header.arena, index.header.arena);
        assert!(replacement.header.committed_bytes < 1024 * 1024);
        assert!(progress.outcome.index_reclamation_pending);
        assert!(old_path.exists());
        assert_eq!(fs::read(fixture.backend.admin.join(INDEX_FILE))?, old_bytes);
        (old_reader, replacement, progress)
    };

    checked_publication::publish_index(
        &fixture.backend,
        &fixture.original,
        &replacement,
        &mut progress,
        &mut || Ok(()),
        1,
    )?;
    assert!(!old_path.exists());
    assert_eq!(progress.outcome.durable_objects, 1);
    assert!(!progress.outcome.index_reclamation_pending);
    let next = replacement.snapshot();
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let reader = next.reader(&fixture.backend, &mut operation)?;
    let mut cursor = reader.cursor(&mut operation)?;
    for ordinal in 0..4_097 {
        assert_eq!(
            cursor.next(&mut operation)?.map(|(key, _)| key),
            Some(Key::object(object(ordinal)))
        );
    }
    assert_eq!(
        cursor.next(&mut operation)?.map(|(key, _)| key),
        Some(Key::pack(PackId([7; 32])))
    );
    assert_eq!(cursor.next(&mut operation)?, None);
    let mut old_cursor = old_reader.cursor(&mut operation)?;
    for ordinal in 0..4_096 {
        assert_eq!(
            old_cursor.next(&mut operation)?.map(|(key, _)| key),
            Some(Key::object(object(ordinal)))
        );
    }
    assert_eq!(
        old_cursor.next(&mut operation)?.map(|(key, _)| key),
        Some(Key::pack(PackId([7; 32])))
    );
    assert_eq!(old_cursor.next(&mut operation)?, None);
    drop(old_cursor);
    drop(old_reader);
    drop(cursor);
    drop(reader);
    drop(next);
    drop(index);
    assert_eq!(fixture.quota.resources.usage()?, baseline);
    Ok(())
}

#[test]
fn placement_full_ram_object_population_uses_fixed_original_buffers() -> Result<(), FixtureError> {
    const OBJECTS: u64 = 393_216;
    let fixture = Fixture::new()?;
    let baseline = fixture.quota.resources.usage()?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut builder = super::index_build::Builder::new(wire::Header::empty([12; 32]), &operation)?;
    for ordinal in 0..OBJECTS {
        builder.push(
            &fixture.backend,
            Key::object(object(ordinal)),
            value(ordinal),
            &mut operation,
        )?;
        let (descriptors, resident) = fixture.quota.resources.usage()?;
        assert!(descriptors - baseline.0 <= 2);
        assert!(resident - baseline.1 <= 6 * wire::PAGE_BYTES as u64 + 65_536);
    }
    let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
    terminal.cleanup?;
    let snapshot = terminal.result?.snapshot();
    assert_eq!(snapshot.header.count, OBJECTS);
    let reader = snapshot.reader(&fixture.backend, &mut operation)?;
    let mut cursor = reader.cursor(&mut operation)?;
    for ordinal in 0..OBJECTS {
        assert_eq!(
            cursor.next(&mut operation)?,
            Some((Key::object(object(ordinal)), value(ordinal)))
        );
    }
    assert_eq!(cursor.next(&mut operation)?, None);
    drop(cursor);
    drop(reader);
    drop(snapshot);
    assert_eq!(fixture.quota.resources.usage()?, baseline);
    Ok(())
}

#[test]
fn placement_shrink_to_inline_reclaims_actual_previous_arena() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let mut builder = super::index_build::Builder::new(wire::Header::empty([23; 32]), &operation)?;
    for ordinal in 0..65 {
        builder.push(
            &fixture.backend,
            Key::object(object(ordinal)),
            value(ordinal),
            &mut operation,
        )?;
    }
    builder.push(
        &fixture.backend,
        Key::pack(PackId([7; 32])),
        Value::pack(wire::PackRecord {
            physical_bytes: 128,
            objects: 65,
            logical_bytes: 65,
        }),
        &mut operation,
    )?;
    let terminal = builder.terminate(&fixture.backend, &mut operation, Ok(()));
    terminal.cleanup?;
    let encoded = terminal.result?;
    fixture.backend.publish_index(&encoded)?;
    let mut index = encoded.snapshot();
    for ordinal in 0..2 {
        let old_identity = index
            .header
            .arena
            .expect("more than sixty-four rows requires an arena");
        let old_name = index_io::arena_name(old_identity);
        let old_path = fixture
            .backend
            .admin
            .join(std::str::from_utf8(&old_name).unwrap());
        let mut progress = checked_publication::Progress::default();
        let (replacement, _, empty) = maintenance::removed(
            &fixture.backend,
            &index,
            object(ordinal),
            &mut operation,
            &mut progress,
        )?
        .unwrap();
        assert!(!empty);
        if ordinal == 1 {
            assert!(replacement.header.arena.is_none());
            assert!(progress.obsolete_arenas.contains(&Some(old_identity)));
            assert!(progress.outcome.index_reclamation_pending);
        }
        checked_publication::publish_index(
            &fixture.backend,
            &fixture.original,
            &replacement,
            &mut progress,
            &mut || Ok(()),
            1,
        )?;
        if ordinal == 1 {
            assert!(!old_path.exists());
            assert!(!progress.outcome.index_reclamation_pending);
        }
        index = replacement.snapshot();
    }
    assert_eq!(index.header.count, 63);
    assert_eq!(index.header.packs, 1);
    assert_eq!(index.header.records, 64);
    Ok(())
}
