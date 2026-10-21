//! Exercises real private-leaf Native writers without pretending to fund J.

use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};

fn fixture() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let journal = Journal::open_gate_target_fixture_v1(
        directory.path(), uid, aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1::State, JournalLimits::default(),
    ).unwrap();
    (directory, journal)
}

fn shape(journal: &Journal, directory: &std::path::Path) -> CacheHeldWriterShapeV1 {
    // The same native observation body runs on an actual private fixture.
    // No fixed Cache owner, J payment or positive held lane is fabricated.
    let mut position = crate::journal::CreateStorageWriterPositionOriginalV1::default();
    position.capture_fixture_once(journal, directory);
    journal.cache_held_shape_from_observed_v1(&position).unwrap()
}

fn require_shape(original: &CacheHeldWriterShapeV1, journal: &Journal, directory: &std::path::Path) -> Result<(), JournalError> {
    let mut position = crate::journal::CreateStorageWriterPositionOriginalV1::default();
    position.capture_fixture_once(journal, directory);
    original.require_observed(journal, &position)
}

fn put(id: u8) -> JournalTransaction {
    JournalTransaction::new([id; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, vec![id], vec![id],
    )]).unwrap()
}

#[test]
fn saved_original_shape_refuses_growth_without_becoming_a_new_price() {
    let (directory, mut journal) = fixture();
    let original = shape(&journal, directory.path());
    require_shape(&original, &journal, directory.path()).unwrap();

    journal.commit(&put(1)).unwrap();

    assert!(require_shape(&original, &journal, directory.path()).is_err());
    assert_eq!(original.coordinates.next, 1);
    assert_eq!(original.coordinates.end, 0);
    assert!(shape(&journal, directory.path()).coordinates.end > 0);
}

#[test]
fn saved_original_shape_refuses_truncation_and_replaced_name() {
    let (directory, mut journal) = fixture();
    journal.commit(&put(1)).unwrap();
    let original = shape(&journal, directory.path());
    let path = directory.path().join("state.journal");
    let bytes = fs::read(&path).unwrap();

    fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(1).unwrap();

    assert!(require_shape(&original, &journal, directory.path()).is_err());
    fs::rename(&path, directory.path().join("previous.journal")).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(require_shape(&original, &journal, directory.path()).is_err());
}

#[test]
fn equal_positions_on_another_actual_writer_do_not_match_original_shape() {
    let (first_directory, first) = fixture();
    let (second_directory, second) = fixture();
    let original = shape(&first, first_directory.path());

    assert_eq!(first.snapshot_sequence(), second.snapshot_sequence());
    assert!(require_shape(&original, &second, second_directory.path()).is_err());
    require_shape(&original, &first, first_directory.path()).unwrap();
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

    assert!(matches!(returned, Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::ProtectedBoundary))));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(journal.snapshot_sequence(), 1);
    assert!(journal.records(RecordNamespace::CreateStorageHistory).next().is_none());
}
