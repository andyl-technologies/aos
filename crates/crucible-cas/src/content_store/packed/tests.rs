//! Packed index internals: sorted files at scale, journal recovery,
//! compaction against a reference model, external sorting, and in-place
//! migration of legacy whole-file indexes.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;

use tempfile::TempDir;

use super::external_sort::ExternalSorter;
use super::index_records::{IndexRecord, IndexRoot, PackRecord};
use super::journal::JOURNAL_RECORD_BYTES;
use super::migration::{LegacyIndex, encode_legacy_index};
use super::sorted_file::{SortedFile, SortedFileIdentity, SortedFileWriter, SortedRecord};
use super::*;

const CONFIGURATION: [u8; 32] = [0x17; 32];
const INSTANCE: [u8; 32] = [0x29; 32];
const TARGET_PACK_BYTES: u64 = 64 * 1024;
const READ_LIMIT: u64 = 1024 * 1024;

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const MIGRATION_INTERRUPTION_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_PACK_INDEX_MIGRATION_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const MIGRATION_INTERRUPTION_ROOT_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_PACK_INDEX_MIGRATION_ROOT";
#[cfg(feature = "destructive-recovery-faults")]
const MIGRATION_INTERRUPTION_TEST_NAME: &str =
    "content_store::packed::tests::interrupted_migration_keeps_the_legacy_index_authoritative";

fn synthetic_id(ordinal: u64) -> ContentId {
    ContentId::for_bytes(ObjectKind::RamExtent, 1, &ordinal.to_be_bytes())
}

fn synthetic_pack(ordinal: u64) -> PackId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"synthetic pack");
    hasher.update(&ordinal.to_be_bytes());
    PackId(*hasher.finalize().as_bytes())
}

fn identity(generation: u64) -> SortedFileIdentity {
    SortedFileIdentity {
        configuration: CONFIGURATION,
        instance: INSTANCE,
        generation,
    }
}

fn write_sorted<R: SortedRecord>(
    directory: &Path,
    prefix: &str,
    records: &[R],
) -> ([u8; 32], PathBuf) {
    let mut writer =
        SortedFileWriter::<R>::create(directory, "index-base", identity(3)).expect("sorted writer");
    for record in records {
        writer.push(*record).expect("push sorted record");
    }
    let digest = writer.finish(prefix).expect("finish sorted file");
    (
        digest,
        directory.join(format!("{prefix}{}", encode_hex(digest))),
    )
}

fn synthetic_base(records: u64) -> Vec<IndexRecord> {
    let mut base = (0..records)
        .map(|ordinal| IndexRecord {
            id: synthetic_id(ordinal),
            entry: IndexEntry {
                pack: synthetic_pack(ordinal / 16),
                offset: 4_096 + (ordinal % 16) * 100,
                length: 100,
            },
        })
        .collect::<Vec<_>>();
    base.sort_by_key(|record| record.id);
    base
}

fn put(store: &PackedBlobBackend, bytes: &[u8]) -> ContentId {
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    store
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .expect("packed put");
    id
}

fn read(store: &PackedBlobBackend, id: ContentId) -> Vec<u8> {
    store
        .read(id, None)
        .and_then(|handle| handle.read_all(READ_LIMIT))
        .expect("packed read")
}

fn admin_files(root: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut files = fs::read_dir(root.join(ADMIN_DIRECTORY))
        .expect("list packed admin directory")
        .map(|entry| entry.expect("packed admin entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn only_admin_file(root: &Path, prefix: &str) -> PathBuf {
    let files = admin_files(root, prefix);
    assert_eq!(files.len(), 1, "expected exactly one {prefix} file");
    files[0].clone()
}

fn current_root(store: &PackedBlobBackend) -> IndexRoot {
    let state = store.lock_state().expect("state lock");
    store
        .with_index(&state, |index| Ok(index.root().clone()))
        .expect("current packed index root")
}

#[test]
fn sorted_base_lookups_and_iteration_scale_beyond_the_retired_object_ceiling() {
    const RECORDS: u64 = 200_000;
    let temporary = TempDir::new().expect("sorted file fixture root");
    let records = synthetic_base(RECORDS);
    let (digest, path) = write_sorted(temporary.path(), "index-base-", &records);

    let file =
        SortedFile::<IndexRecord>::open(&path, CONFIGURATION, INSTANCE).expect("open sorted base");
    assert_eq!(file.record_count(), RECORDS);
    assert_eq!(file.generation(), 3);
    for record in records.iter().step_by(997).chain(records.last()) {
        assert_eq!(file.find(record.id).expect("present lookup"), Some(*record));
    }
    for ordinal in RECORDS..RECORDS + 64 {
        assert_eq!(
            file.find(synthetic_id(ordinal)).expect("absent lookup"),
            None
        );
    }

    let mut streamed = 0_usize;
    for (observed, expected) in file.iter(digest).zip(&records) {
        assert_eq!(observed.expect("authenticated record"), *expected);
        streamed += 1;
    }
    assert_eq!(streamed, records.len());
    assert!(file.iter([0; 32]).any(|record| record.is_err()));
    assert!(matches!(
        SortedFile::<IndexRecord>::open(&path, CONFIGURATION, [0; 32]),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn sorted_files_reject_unordered_corrupt_or_truncated_content() {
    let temporary = TempDir::new().expect("sorted corruption fixture root");
    let records = synthetic_base(200);
    let mut writer =
        SortedFileWriter::<IndexRecord>::create(temporary.path(), "index-base", identity(3))
            .expect("sorted writer");
    writer.push(records[1]).expect("first record");
    assert!(matches!(
        writer.push(records[0]),
        Err(StoreError::Incompatible)
    ));
    drop(writer);
    assert!(directory_entries(temporary.path()).is_empty());

    let (digest, path) = write_sorted(temporary.path(), "index-base-", &records);
    let original = fs::read(&path).expect("sorted file bytes");
    let header = IndexRecord::FORMAT.magic.len() + 72;
    let block_bytes = IndexRecord::FORMAT.record_width * IndexRecord::FORMAT.block_records + 32;

    let mut corrupt_block = original.clone();
    corrupt_block[header + block_bytes + 7] ^= 0x01;
    fs::write(&path, &corrupt_block).expect("corrupt second block");
    let file = SortedFile::<IndexRecord>::open(&path, CONFIGURATION, INSTANCE)
        .expect("block corruption is detected lazily");
    let in_corrupt_block = records[IndexRecord::FORMAT.block_records + 1].id;
    assert!(matches!(
        file.find(in_corrupt_block),
        Err(StoreError::Incompatible)
    ));
    assert!(file.iter(digest).any(|record| record.is_err()));

    let mut corrupt_generation = original.clone();
    corrupt_generation[header - 1] ^= 0x01;
    fs::write(&path, &corrupt_generation).expect("corrupt header generation");
    assert!(matches!(
        SortedFile::<IndexRecord>::open(&path, CONFIGURATION, INSTANCE),
        Err(StoreError::Incompatible)
    ));

    fs::write(&path, &original[..original.len() - 1]).expect("truncate sorted file");
    assert!(matches!(
        SortedFile::<IndexRecord>::open(&path, CONFIGURATION, INSTANCE),
        Err(StoreError::Incompatible)
    ));
}

fn directory_entries(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .expect("list fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .collect()
}

#[test]
fn external_sort_merges_spilled_runs_beyond_the_merge_fan_in() {
    let temporary = TempDir::new().expect("external sort fixture root");
    let records = (0..1_000_u64)
        .map(|ordinal| PackRecord {
            pack: synthetic_pack(ordinal),
            state: PackState {
                live_entries: 1 + ordinal % 7,
                physical_bytes: 1_000 + ordinal,
            },
        })
        .collect::<Vec<_>>();
    let mut expected = records.clone();
    expected.sort_by_key(|record| record.pack);

    // Three-record runs produce 334 runs, which needs a second merge pass.
    for run_records in [3, 10_000] {
        let mut sorter =
            ExternalSorter::<PackRecord>::with_run_records(temporary.path(), run_records);
        for record in &records {
            sorter.push(*record).expect("push sort record");
        }
        let sorted = sorter
            .finish()
            .expect("finish external sort")
            .collect::<Result<Vec<_>, _>>()
            .expect("sorted records");
        assert_eq!(sorted, expected);
    }
    assert!(directory_entries(temporary.path()).is_empty());
}

/// Commits a model-checked mutation and mirrors it in the reference maps.
fn commit_and_mirror(
    directory: &index::IndexDirectory<'_>,
    view: &mut PackIndex,
    record: JournalRecord,
    entries: &mut BTreeMap<ContentId, IndexEntry>,
    packs: &mut BTreeMap<PackId, PackState>,
) {
    directory
        .commit(view, record)
        .expect("commit journal record");
    match record.operation {
        JournalOperation::Put => {
            entries.insert(record.id, record.entry);
            let state = packs.entry(record.entry.pack).or_insert(PackState {
                live_entries: 0,
                physical_bytes: record.pack_physical_bytes,
            });
            state.live_entries += 1;
        }
        JournalOperation::Delete => {
            entries.remove(&record.id);
            let state = packs.get_mut(&record.entry.pack).expect("model pack");
            state.live_entries -= 1;
            if state.live_entries == 0 {
                packs.remove(&record.entry.pack);
            }
        }
    }
}

fn assert_view_matches(
    view: &PackIndex,
    entries: &BTreeMap<ContentId, IndexEntry>,
    packs: &BTreeMap<PackId, PackState>,
) {
    let observed_entries = view
        .entries()
        .map(|record| record.map(|record| (record.id, record.entry)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .expect("merged entries");
    assert_eq!(&observed_entries, entries);
    let observed_packs = view
        .packs()
        .map(|record| record.map(|record| (record.pack, record.state)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .expect("merged packs");
    assert_eq!(&observed_packs, packs);

    let totals = view.root().totals;
    assert_eq!(totals.logical_objects, entries.len() as u64);
    assert_eq!(
        totals.logical_bytes,
        entries.values().map(|entry| entry.length).sum::<u64>()
    );
    assert_eq!(totals.packs, packs.len() as u64);
    assert_eq!(
        totals.physical_bytes,
        packs
            .values()
            .map(|state| state.physical_bytes)
            .sum::<u64>()
    );
}

#[test]
fn journal_commits_and_compactions_match_a_reference_model_beyond_the_retired_ceiling() {
    const BASE_RECORDS: u64 = 70_000;
    const THRESHOLD: u64 = 32;
    let temporary = TempDir::new().expect("index model fixture root");
    let directory = index::IndexDirectory {
        admin: temporary.path(),
        configuration: CONFIGURATION,
        policy: index::CompactionPolicy::new(THRESHOLD, THRESHOLD),
    };

    let mut entries = synthetic_base(BASE_RECORDS)
        .into_iter()
        .map(|record| (record.id, record.entry))
        .collect::<BTreeMap<_, _>>();
    let mut packs = BTreeMap::new();
    for entry in entries.values() {
        packs
            .entry(entry.pack)
            .or_insert(PackState {
                live_entries: 0,
                physical_bytes: 4_096 + 16 * 100,
            })
            .live_entries += 1;
    }
    let mut build = directory
        .build(INSTANCE, 0, PackOrder::Sorted)
        .expect("start synthetic base");
    for (id, entry) in &entries {
        build.push_entry(*id, *entry).expect("push base entry");
    }
    for (pack, state) in &packs {
        build.push_pack(*pack, *state).expect("push base pack");
    }
    let staged = build.finish().expect("stage synthetic base");
    let mut view = directory
        .open_view(staged.root(0, None))
        .expect("open staged view");
    directory.publish(&view).expect("publish synthetic root");
    let initial_base = view.root().base_digest;

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next_random = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for step in 0..400_u64 {
        let record = if step % 3 == 0 {
            let position = usize::try_from(next_random() % entries.len() as u64).expect("position");
            let (id, entry) = entries
                .iter()
                .nth(position)
                .map(|(id, entry)| (*id, *entry))
                .expect("victim");
            JournalRecord {
                operation: JournalOperation::Delete,
                id,
                entry,
                pack_physical_bytes: packs[&entry.pack].physical_bytes,
            }
        } else {
            JournalRecord {
                operation: JournalOperation::Put,
                id: synthetic_id(1_000_000 + step),
                entry: IndexEntry {
                    pack: synthetic_pack(1_000_000 + step),
                    offset: 200,
                    length: 50,
                },
                pack_physical_bytes: 250,
            }
        };
        commit_and_mirror(&directory, &mut view, record, &mut entries, &mut packs);
        assert_eq!(
            view.get(record.id).expect("mutated lookup"),
            entries.get(&record.id).copied()
        );
    }

    // Re-adding a present object and deleting with a stale entry both fail
    // without advancing the committed root.
    let generation = view.root().generation;
    let (present, present_entry) = entries
        .iter()
        .next()
        .map(|(id, entry)| (*id, *entry))
        .expect("present");
    let duplicate = JournalRecord {
        operation: JournalOperation::Put,
        id: present,
        entry: IndexEntry {
            pack: synthetic_pack(9_999_999),
            offset: 200,
            length: 50,
        },
        pack_physical_bytes: 250,
    };
    assert!(matches!(
        directory.commit(&mut view, duplicate),
        Err(StoreError::Incompatible)
    ));
    let stale_delete = JournalRecord {
        operation: JournalOperation::Delete,
        id: present,
        entry: IndexEntry {
            length: present_entry.length + 1,
            ..present_entry
        },
        pack_physical_bytes: packs[&present_entry.pack].physical_bytes,
    };
    assert!(matches!(
        directory.commit(&mut view, stale_delete),
        Err(StoreError::Incompatible)
    ));
    assert_eq!(view.root().generation, generation);

    assert_ne!(
        view.root().base_digest,
        initial_base,
        "compaction never ran"
    );
    assert!(view.root().journal_records < THRESHOLD);
    assert_eq!(view.root().generation, 400);
    assert_view_matches(&view, &entries, &packs);

    let reloaded = directory.load(None).expect("cold reload");
    assert_eq!(reloaded.digest(), view.digest());
    assert_view_matches(&reloaded, &entries, &packs);

    // A view of an older root over the same base extends by replaying only
    // the newly committed records.
    while view.root().journal_records + 4 >= THRESHOLD {
        let record = JournalRecord {
            operation: JournalOperation::Put,
            id: synthetic_id(2_000_000 + view.root().generation),
            entry: IndexEntry {
                pack: synthetic_pack(2_000_000 + view.root().generation),
                offset: 200,
                length: 50,
            },
            pack_physical_bytes: 250,
        };
        commit_and_mirror(&directory, &mut view, record, &mut entries, &mut packs);
    }
    let stale = directory.load(None).expect("view before extension");
    for offset in 0..3 {
        let record = JournalRecord {
            operation: JournalOperation::Put,
            id: synthetic_id(3_000_000 + offset),
            entry: IndexEntry {
                pack: synthetic_pack(3_000_000 + offset),
                offset: 200,
                length: 50,
            },
            pack_physical_bytes: 250,
        };
        commit_and_mirror(&directory, &mut view, record, &mut entries, &mut packs);
    }
    assert_eq!(stale.root().base_digest, view.root().base_digest);
    let extended = directory.load(Some(stale)).expect("incremental reload");
    assert_eq!(extended.digest(), view.digest());
    assert_view_matches(&extended, &entries, &packs);

    // Compaction removed every superseded file; foreign names survive a sweep.
    assert_eq!(directory.sweep_orphans(&view).expect("clean sweep"), 0);
    let orphan_base = temporary
        .path()
        .join(format!("index-base-{}", "0".repeat(64)));
    let orphan_staging = temporary.path().join(".index-base.tmp-1-1");
    let foreign = temporary.path().join("operator-notes");
    for path in [&orphan_base, &orphan_staging, &foreign] {
        fs::write(path, b"fixture").expect("write sweep fixture");
    }
    assert_eq!(directory.sweep_orphans(&view).expect("orphan sweep"), 2);
    assert!(!orphan_base.exists() && !orphan_staging.exists());
    assert!(foreign.exists());
}

#[test]
fn uncommitted_journal_tail_is_discarded_and_lost_committed_records_fail_closed() {
    let temporary = TempDir::new().expect("journal recovery fixture root");
    let root = temporary.path().join("packed");
    let store =
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("packed backend");
    let first = put(&store, b"first committed object");
    let root_path = root.join(ADMIN_DIRECTORY).join(index::ROOT_FILE);
    let committed_root = fs::read(&root_path).expect("committed root");
    let second = put(&store, b"second object");
    drop(store);

    // Restoring the earlier root reproduces an interruption after the second
    // journal append and pack publication but before its root publication.
    let journal = only_admin_file(&root, "index-journal-");
    let with_second = fs::metadata(&journal).expect("journal length").len();
    fs::write(&root_path, &committed_root).expect("restore earlier root");
    fs::OpenOptions::new()
        .append(true)
        .open(&journal)
        .and_then(|mut file| file.write_all(b"torn"))
        .expect("append torn bytes");

    let reopened =
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("recover tail");
    assert_eq!(
        fs::metadata(&journal).expect("truncated journal").len(),
        with_second - JOURNAL_RECORD_BYTES as u64
    );
    assert_eq!(read(&reopened, first), b"first committed object");
    assert!(
        !reopened
            .contains(second)
            .expect("uncommitted object absent")
    );
    let cleanup = reopened
        .cleanup_incomplete_packs()
        .expect("reclaim orphan pack");
    assert_eq!(cleanup.removed_unreferenced_packs(), 1);
    assert_eq!(put(&reopened, b"second object"), second);
    assert_eq!(read(&reopened, second), b"second object");
    drop(reopened);

    let committed = fs::read(&journal).expect("committed journal");
    let mut corrupt = committed.clone();
    let last_record = committed.len() - JOURNAL_RECORD_BYTES;
    corrupt[last_record + 40] ^= 0x01;
    fs::write(&journal, &corrupt).expect("corrupt committed record");
    assert!(matches!(
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES),
        Err(StoreError::Incompatible)
    ));
    fs::write(&journal, &committed[..committed.len() - 1]).expect("drop committed byte");
    assert!(matches!(
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES),
        Err(StoreError::Incompatible)
    ));
    fs::write(&journal, &committed).expect("restore journal");
    let restored =
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("restored journal");
    assert_eq!(read(&restored, second), b"second object");
}

#[test]
fn compaction_preserves_objects_across_restart_repack_and_deletion() {
    let temporary = TempDir::new().expect("compaction fixture root");
    let root = temporary.path().join("packed");
    let open = || {
        PackedBlobBackend::open_with_journal_threshold("packed", &root, TARGET_PACK_BYTES, 2)
            .expect("compacting packed backend")
    };
    let store = open();
    let objects = (0..9_u8)
        .map(|ordinal| {
            let bytes = vec![ordinal; 512 + usize::from(ordinal)];
            (put(&store, &bytes), bytes)
        })
        .collect::<Vec<_>>();

    let compacted = current_root(&store);
    assert!(compacted.journal_records < 2);
    assert_eq!(compacted.base_records + compacted.journal_records, 9);
    for prefix in ["index-base-", "pack-table-", "index-journal-"] {
        only_admin_file(&root, prefix);
    }
    let accounting = store.accounting().expect("compacted accounting");
    assert_eq!(accounting.logical_objects(), 9);
    assert_eq!(accounting.packs(), 9);
    assert_eq!(accounting.generation(), 9);
    drop(store);

    let restarted = open();
    for (id, bytes) in &objects {
        assert_eq!(&read(&restarted, *id), bytes);
    }
    let plan = restarted.plan_repack().expect("plan repack");
    let report = restarted.apply_repack(&plan).expect("apply repack");
    assert_eq!(report.after().packs(), 1);
    assert_eq!(report.removed_packs(), 9);
    for prefix in ["index-base-", "pack-table-", "index-journal-"] {
        only_admin_file(&root, prefix);
    }

    let mut fence = restarted
        .acquire_inventory_fence()
        .expect("inventory fence");
    for (id, _bytes) in &objects[..4] {
        assert_eq!(
            fence.delete_candidate(*id).expect("delete candidate"),
            PlannedDeleteDisposition::Deleted
        );
    }
    let summary = fence
        .visit_inventory(&mut |_record| Ok(()))
        .expect("inventory");
    assert_eq!(summary.objects(), 5);
    drop(fence);
    drop(restarted);

    let reopened = open();
    for (id, bytes) in &objects[..4] {
        assert!(
            !reopened.contains(*id).expect("deleted object"),
            "{bytes:?}"
        );
    }
    for (id, bytes) in &objects[4..] {
        assert_eq!(&read(&reopened, *id), bytes);
    }
    let accounting = reopened.accounting().expect("final accounting");
    assert_eq!(accounting.logical_objects(), 5);
    assert_eq!(accounting.packs(), 1);
}

/// Rewrites `root` as a legacy store and returns its expected accounting.
fn downgrade_to_legacy(root: &Path) -> (PackedStorageAccounting, IndexRoot) {
    let store = PackedBlobBackend::open("packed", root, TARGET_PACK_BYTES).expect("packed backend");
    let accounting = store.accounting().expect("accounting before migration");
    let state = store.lock_state().expect("state lock");
    let (index_root, entries) = store
        .with_index(&state, |index| {
            let entries = index
                .entries()
                .map(|record| record.map(|record| (record.id, record.entry)))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((index.root().clone(), entries))
        })
        .expect("current entries");
    drop(state);
    let configuration = store.configuration;
    drop(store);

    for prefix in ["index-v2", "index-base-", "pack-table-", "index-journal-"] {
        for path in admin_files(root, prefix) {
            fs::remove_file(path).expect("remove v2 index file");
        }
    }
    let legacy = LegacyIndex {
        instance: index_root.instance,
        generation: index_root.generation,
        last_repack_plan: index_root.last_repack_plan,
        entries,
    };
    fs::write(
        migration::legacy_index_path(&root.join(ADMIN_DIRECTORY)),
        encode_legacy_index(&legacy, configuration),
    )
    .expect("write legacy index");
    (accounting, index_root)
}

fn seed_mixed_store(root: &Path) -> Vec<(ContentId, Vec<u8>)> {
    let store = PackedBlobBackend::open("packed", root, TARGET_PACK_BYTES).expect("packed backend");
    let mut objects = Vec::new();
    for ordinal in 0..3_u8 {
        let bytes = vec![0x40 + ordinal; 700];
        objects.push((put(&store, &bytes), bytes));
    }
    let plan = store.plan_repack().expect("plan seed repack");
    store.apply_repack(&plan).expect("apply seed repack");
    let loose = b"one-object pack after repack".to_vec();
    objects.push((put(&store, &loose), loose));
    objects
}

#[test]
fn legacy_index_migrates_in_place_with_identity_and_contents_preserved() {
    let temporary = TempDir::new().expect("migration fixture root");
    let root = temporary.path().join("packed");
    let objects = seed_mixed_store(&root);
    let (accounting, legacy_root) = downgrade_to_legacy(&root);
    let legacy_path = migration::legacy_index_path(&root.join(ADMIN_DIRECTORY));

    let migrated = PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("migrate");
    assert!(!legacy_path.exists());
    let root_after = current_root(&migrated);
    assert_eq!(root_after.instance, legacy_root.instance);
    assert_eq!(root_after.generation, legacy_root.generation);
    assert_eq!(root_after.journal_records, 0);
    assert_eq!(
        migrated.accounting().expect("migrated accounting"),
        accounting
    );
    for (id, bytes) in &objects {
        assert_eq!(&read(&migrated, *id), bytes);
    }
    let extra = put(&migrated, b"written after migration");
    assert_eq!(read(&migrated, extra), b"written after migration");
}

#[test]
fn interrupted_or_superseded_legacy_migration_converges_and_corruption_fails_closed() {
    let temporary = TempDir::new().expect("migration recovery fixture root");
    let root = temporary.path().join("packed");
    let objects = seed_mixed_store(&root);
    let admin = root.join(ADMIN_DIRECTORY);
    let legacy_path = migration::legacy_index_path(&admin);
    let (accounting, _legacy_root) = downgrade_to_legacy(&root);
    let legacy_bytes = fs::read(&legacy_path).expect("legacy bytes");
    drop(PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("first migration"));

    // Interrupted after the root publication: the stale legacy file is removed.
    fs::write(&legacy_path, &legacy_bytes).expect("restore superseded legacy index");
    let reopened = PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("reopen");
    assert!(!legacy_path.exists());
    assert_eq!(reopened.accounting().expect("accounting"), accounting);
    drop(reopened);

    // Interrupted before the root publication: staged files exist but no
    // root does, so the legacy index remains authoritative and migration repeats.
    fs::remove_file(admin.join(index::ROOT_FILE)).expect("remove published root");
    fs::write(&legacy_path, &legacy_bytes).expect("restore authoritative legacy index");
    fs::write(
        admin.join(format!("pack-table-{}", "1".repeat(64))),
        b"stale staged table",
    )
    .expect("write stale staged table");
    let repeated =
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("repeat migration");
    assert!(!legacy_path.exists());
    for prefix in ["index-base-", "pack-table-", "index-journal-"] {
        only_admin_file(&root, prefix);
    }
    for (id, bytes) in &objects {
        assert_eq!(&read(&repeated, *id), bytes);
    }
    drop(repeated);

    fs::remove_file(admin.join(index::ROOT_FILE)).expect("remove root again");
    let mut corrupt = legacy_bytes;
    corrupt[60] ^= 0x01;
    fs::write(&legacy_path, &corrupt).expect("write corrupt legacy index");
    assert!(matches!(
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES),
        Err(StoreError::Incompatible)
    ));
    assert!(legacy_path.exists());
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn interrupted_migration_keeps_the_legacy_index_authoritative() {
    if let Some(root) = std::env::var_os(MIGRATION_INTERRUPTION_ROOT_ENVIRONMENT)
        && std::env::var_os(MIGRATION_INTERRUPTION_CHILD_ENVIRONMENT).is_some()
    {
        let _migrated = PackedBlobBackend::open("packed", PathBuf::from(root), TARGET_PACK_BYTES);
        panic!("migration child returned without reaching the injected interruption");
    }

    let temporary = TempDir::new().expect("migration interruption fixture root");
    let root = temporary.path().join("packed");
    let objects = seed_mixed_store(&root);
    let (accounting, _legacy_root) = downgrade_to_legacy(&root);
    let admin = root.join(ADMIN_DIRECTORY);

    let child = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg(MIGRATION_INTERRUPTION_TEST_NAME)
        .arg("--nocapture")
        .env(MIGRATION_INTERRUPTION_CHILD_ENVIRONMENT, "1")
        .env(MIGRATION_INTERRUPTION_ROOT_ENVIRONMENT, &root)
        .env(
            DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
            MIGRATION_INTERRUPTION_TRIGGER,
        )
        .output()
        .expect("run migration interruption child");
    assert_eq!(
        child.status.code(),
        Some(PACK_INDEX_INTERRUPTION_EXIT_CODE),
        "migration child did not stop at the injected point:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
    assert!(migration::legacy_index_path(&admin).exists());
    assert!(!admin.join(index::ROOT_FILE).exists());
    only_admin_file(&root, "index-base-");

    let migrated =
        PackedBlobBackend::open("packed", &root, TARGET_PACK_BYTES).expect("resume migration");
    assert!(!migration::legacy_index_path(&admin).exists());
    assert_eq!(
        migrated.accounting().expect("migrated accounting"),
        accounting
    );
    for (id, bytes) in &objects {
        assert_eq!(&read(&migrated, *id), bytes);
    }
}
