//! Ordering, merging, deduplication, and cleanup of external-sort runs.

// crucible-lint: allow panic-shortcut -- fixture failures localize exact spill behavior.
#![allow(clippy::expect_used)]

use super::*;

fn id(kind: ObjectKind, schema: u32, seed: u8) -> ContentId {
    ContentId::for_bytes(kind, schema, &[seed])
}

fn read_ids(file: &SpillFile) -> Vec<ContentId> {
    let mut reader = file.reader::<ID_RECORD_BYTES>().expect("open spill run");
    let mut ids = Vec::new();
    while let Some(record) = reader.next_record().expect("read spill record") {
        ids.push(decode_ordered_id_record(&record).expect("decode spill record"));
    }
    ids
}

fn directory_storage(parent: &Path) -> SpillStorage {
    SpillStorage::directory(parent, ".crucible-test-spill").expect("work directory")
}

#[test]
fn ordered_records_follow_content_id_order_and_round_trip() {
    for (rank, kind) in KINDS_BY_RANK.iter().enumerate() {
        assert_eq!(usize::from(kind_rank(*kind)), rank);
    }
    let mut ids = KINDS_BY_RANK
        .iter()
        .rev()
        .flat_map(|kind| [id(*kind, 2, 1), id(*kind, 1, 2), id(*kind, 1, 3)])
        .collect::<Vec<_>>();
    for original in &ids {
        assert_eq!(
            decode_ordered_id_record(&ordered_id_record(*original)).expect("decode"),
            *original
        );
    }

    let mut by_record = ids.clone();
    by_record.sort_by_key(|id| ordered_id_record(*id));
    ids.sort();

    assert_eq!(by_record, ids);
}

#[test]
fn external_sort_spills_merges_in_groups_and_deduplicates() {
    let parent = tempfile::tempdir().expect("spill parent");
    for storage in [directory_storage(parent.path()), SpillStorage::Memory] {
        // Three-record runs over 1,000 pushes force more runs than one merge
        // may read, so the result passes through a second merge level.
        let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&storage, "ids", 3);
        let mut expected = Vec::new();
        for value in 0..1_000_u32 {
            let seed = (value * 7_919 % 500) as u8;
            let schema = value % 500 / 256 + 1;
            let content = id(ObjectKind::Observation, schema, seed);
            sorter.push(ordered_id_record(content)).expect("push id");
            expected.push(content);
        }
        expected.sort();
        expected.dedup();

        let sorted = sorter.finish().expect("finish sort");

        assert_eq!(read_ids(&sorted), expected);
        assert_eq!(sorted.records(), expected.len() as u64);
    }
}

#[test]
fn retaining_sorter_keeps_repeated_records_adjacent() {
    let parent = tempfile::tempdir().expect("spill parent");
    let storage = directory_storage(parent.path());
    let mut sorter =
        ExternalSorter::<ID_RECORD_BYTES>::new_retaining_duplicates(&storage, "ids", 2);
    let repeated = id(ObjectKind::Finding, 1, 9);
    let other = id(ObjectKind::CampaignFact, 1, 4);
    for content in [repeated, other, repeated, repeated] {
        sorter.push(ordered_id_record(content)).expect("push id");
    }

    let sorted = sorter.finish().expect("finish sort");

    assert_eq!(read_ids(&sorted), vec![other, repeated, repeated, repeated]);
}

#[test]
fn sorted_membership_advances_forward_only() {
    let storage = SpillStorage::Memory;
    let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&storage, "ids", 2);
    let present = [id(ObjectKind::Trace, 1, 1), id(ObjectKind::Trace, 1, 7)];
    for content in present {
        sorter.push(ordered_id_record(content)).expect("push id");
    }
    let sorted = sorter.finish().expect("finish sort");
    let mut queries = present.to_vec();
    queries.push(id(ObjectKind::Trace, 1, 4));
    queries.sort();

    let mut membership = SortedRecords::<ID_RECORD_BYTES>::open(&sorted).expect("open");
    let found = queries
        .iter()
        .map(|query| {
            membership
                .contains(&ordered_id_record(*query))
                .expect("membership")
        })
        .collect::<Vec<_>>();

    let expected = queries
        .iter()
        .map(|query| present.contains(query))
        .collect::<Vec<_>>();
    assert_eq!(found, expected);
}

#[test]
fn empty_sorter_yields_an_empty_run() {
    let sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&SpillStorage::Memory, "ids", RUN_RECORDS);

    let sorted = sorter.finish().expect("finish sort");

    assert_eq!(sorted.records(), 0);
    assert!(read_ids(&sorted).is_empty());
}

#[test]
fn work_directory_and_files_are_removed_when_the_last_handle_drops() {
    let parent = tempfile::tempdir().expect("spill parent");
    let storage = directory_storage(parent.path());
    let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&storage, "ids", 2);
    for seed in 0..5 {
        sorter
            .push(ordered_id_record(id(ObjectKind::Trace, 1, seed)))
            .expect("push id");
    }
    let sorted = sorter.finish().expect("finish sort");
    drop(storage);
    assert_eq!(
        fs::read_dir(parent.path()).expect("parent").count(),
        1,
        "a live spill run keeps its work directory"
    );

    drop(sorted);

    assert_eq!(fs::read_dir(parent.path()).expect("parent").count(), 0);
}

#[test]
fn frames_replay_in_order_and_reject_oversized_lengths() {
    let parent = tempfile::tempdir().expect("spill parent");
    for storage in [directory_storage(parent.path()), SpillStorage::Memory] {
        let mut writer = FrameWriter::create(&storage, "pages").expect("frame run");
        for frame in [&b"first"[..], b"", b"third frame"] {
            writer.push(frame).expect("push frame");
        }
        let run = writer.finish().expect("finish frames");

        let mut reader = run.frames().expect("open frames");
        let mut frames = Vec::new();
        while let Some(frame) = reader.next_frame(64).expect("read frame") {
            frames.push(frame);
        }

        assert_eq!(
            frames,
            vec![b"first".to_vec(), Vec::new(), b"third frame".to_vec()]
        );
        let mut bounded = run.frames().expect("reopen frames");
        assert_eq!(
            bounded.next_frame(4).expect_err("oversized frame").kind(),
            io::ErrorKind::InvalidData
        );
    }
}
