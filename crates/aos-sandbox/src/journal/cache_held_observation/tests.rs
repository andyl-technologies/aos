//! Exercises real private-leaf Native writers without pretending to fund J.

use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use crate::journal::{JournalRecord, JournalTransaction};

fn fixture() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let (journal, _) = Journal::open_protected_at_uid(
        directory.path(), "state.journal", JournalLimits::default(), uid,
    ).unwrap();
    (directory, journal)
}

fn shape(journal: &Journal) -> CacheHeldWriterShapeV1 {
    // The existing Controller test recipe accepts this protected private leaf;
    // no fixed Cache-root owner, J payment or positive held lane is fabricated.
    let mut position = crate::journal::CreateStorageWriterPositionOriginalV1::default();
    position.capture_once(journal, crate::controller_resource_reservation::HistoryRoleV1::Controller);
    journal.cache_held_shape_from_observed_v1(&position).unwrap()
}

fn require_shape(original: &CacheHeldWriterShapeV1, journal: &Journal) -> Result<(), JournalError> {
    let mut position = crate::journal::CreateStorageWriterPositionOriginalV1::default();
    position.capture_once(journal, crate::controller_resource_reservation::HistoryRoleV1::Controller);
    original.require_observed(journal, &position)
}

fn put(id: u8) -> JournalTransaction {
    JournalTransaction::new([id; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, vec![id], vec![id],
    )]).unwrap()
}

#[test]
fn saved_original_shape_refuses_growth_without_becoming_a_new_price() {
    let (_directory, mut journal) = fixture();
    let original = shape(&journal);
    require_shape(&original, &journal).unwrap();

    journal.commit(&put(1)).unwrap();

    assert!(require_shape(&original, &journal).is_err());
    assert_eq!(original.coordinates.next, 1);
    assert_eq!(original.coordinates.end, 0);
    assert!(shape(&journal).coordinates.end > 0);
}

#[test]
fn saved_original_shape_refuses_truncation_and_replaced_name() {
    let (directory, mut journal) = fixture();
    journal.commit(&put(1)).unwrap();
    let original = shape(&journal);
    let path = directory.path().join("state.journal");
    let bytes = fs::read(&path).unwrap();

    journal.native.set_length_for_fixture(1).unwrap();

    assert!(require_shape(&original, &journal).is_err());
    fs::rename(&path, directory.path().join("previous.journal")).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(require_shape(&original, &journal).is_err());
}

#[test]
fn equal_positions_on_another_actual_writer_do_not_match_original_shape() {
    let (_first_directory, first) = fixture();
    let (_second_directory, second) = fixture();
    let original = shape(&first);

    assert_eq!(first.snapshot_sequence(), second.snapshot_sequence());
    assert!(require_shape(&original, &second).is_err());
    require_shape(&original, &first).unwrap();
}

#[test]
fn passive_namespace_history_cannot_enter_the_ordinary_native_appender() {
    let (directory, mut journal) = fixture();
    let path = directory.path().join("state.journal");
    let before = fs::read(&path).unwrap();
    let transaction = JournalTransaction::new([2; 16], vec![JournalRecord::put(
        RecordNamespace::CreateStorageHistory, vec![1], vec![2],
    )]).unwrap();

    let returned = journal.commit(&transaction);

    assert!(matches!(returned, Err(JournalError::ProtectedBoundary)));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(journal.snapshot_sequence(), 1);
    assert!(journal.records(RecordNamespace::CreateStorageHistory).next().is_none());
}
