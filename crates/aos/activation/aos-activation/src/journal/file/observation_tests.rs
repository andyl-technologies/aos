//! Verifies concurrent observations without weakening writer custody.

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek as _, SeekFrom, Write as _};

use serde::{Deserialize, Serialize};

use super::{FileJournal, JournalError, JournalLimits, JournalPayload, read_verified_prefix};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Event {
    counter: u64,
}

impl JournalPayload for Event {
    fn validate_for_journal(&self, _: JournalLimits) -> Result<(), JournalError> {
        // The fixture has no recursively allocated or unbounded fields.
        Ok(())
    }
}

#[test]
fn observation_preserves_held_writer_and_its_verified_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("events.journal");
    let limits = JournalLimits::default();
    let mut writer = FileJournal::<Event>::open(&path, limits).unwrap().journal;
    writer.append(&Event { counter: 1 }).unwrap();
    let before = fs::read(&path).unwrap();

    let snapshot = FileJournal::<Event>::observe_snapshot(&path, limits).unwrap();

    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(snapshot.records()[0].body(), &Event { counter: 1 });
    assert_eq!(snapshot.verified_bytes(), before.len() as u64);
    assert_eq!(snapshot.incomplete_tail_bytes(), 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(FileJournal::<Event>::read_only_snapshot(&path, limits).is_err());
    assert!(FileJournal::<Event>::open(&path, limits).is_err());

    writer.append(&Event { counter: 2 }).unwrap();
    assert_eq!(snapshot.records().len(), 1);
    let later = FileJournal::<Event>::observe_snapshot(&path, limits).unwrap();
    assert_eq!(later.records().len(), 2);
    assert_eq!(later.records()[1].sequence(), 2);
    assert_eq!(later.records()[1].body(), &Event { counter: 2 });
}

#[test]
fn captured_cut_excludes_an_available_complete_suffix_and_reports_partial_frame() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("events.journal");
    let limits = JournalLimits::default();
    let mut writer = FileJournal::<Event>::open(&path, limits).unwrap().journal;
    writer.append(&Event { counter: 1 }).unwrap();
    let captured_length = fs::metadata(&path).unwrap().len();
    writer.append(&Event { counter: 2 }).unwrap();
    let bytes = fs::read(&path).unwrap();

    for tail_bytes in [0, 7] {
        let cut = captured_length + tail_bytes;
        let mut reader = Cursor::new(&bytes);
        let report = read_verified_prefix::<Event>(&mut reader, &path, limits, cut).unwrap();

        assert_eq!(report.records().len(), 1);
        assert_eq!(report.records()[0].body(), &Event { counter: 1 });
        assert_eq!(report.valid_bytes(), captured_length);
        assert_eq!(report.discarded_torn_bytes(), tail_bytes);
    }
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn observation_rejects_truncation_before_the_captured_endpoint() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("events.journal");
    let limits = JournalLimits::default();
    let mut writer = FileJournal::<Event>::open(&path, limits).unwrap().journal;
    writer.append(&Event { counter: 1 }).unwrap();
    let first_length = fs::metadata(&path).unwrap().len();
    writer.append(&Event { counter: 2 }).unwrap();
    let mut reader = File::open(&path).unwrap();
    let captured_length = reader.metadata().unwrap().len();

    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(first_length)
        .unwrap();
    let before = fs::read(&path).unwrap();
    let error =
        read_verified_prefix::<Event>(&mut reader, &path, limits, captured_length).unwrap_err();

    assert!(matches!(error, JournalError::Io { source, .. }
        if source.kind() == std::io::ErrorKind::UnexpectedEof));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(FileJournal::<Event>::open(&path, limits).is_err());
}

#[test]
fn observation_reports_incomplete_tail_without_repair_under_writer_lock() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("events.journal");
    let limits = JournalLimits::default();
    let mut writer = FileJournal::<Event>::open(&path, limits).unwrap().journal;
    writer.append(&Event { counter: 1 }).unwrap();
    let complete_length = fs::metadata(&path).unwrap().len();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"AOS")
        .unwrap();
    let before = fs::read(&path).unwrap();

    let snapshot = FileJournal::<Event>::observe_snapshot(&path, limits).unwrap();

    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(snapshot.verified_bytes(), complete_length);
    assert_eq!(snapshot.incomplete_tail_bytes(), 3);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(FileJournal::<Event>::open(&path, limits).is_err());
}

#[test]
fn observation_rejects_complete_corruption_without_mutating_or_unlocking() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("events.journal");
    let limits = JournalLimits::default();
    let mut writer = FileJournal::<Event>::open(&path, limits).unwrap().journal;
    writer.append(&Event { counter: 1 }).unwrap();
    let mut corrupt = fs::read(&path).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&corrupt).unwrap();

    let error = FileJournal::<Event>::observe_snapshot(&path, limits).unwrap_err();

    assert!(matches!(error, JournalError::Corrupt { .. }));
    assert_eq!(fs::read(&path).unwrap(), corrupt);
    assert!(FileJournal::<Event>::read_only_snapshot(&path, limits).is_err());
    assert!(FileJournal::<Event>::open(&path, limits).is_err());
}
