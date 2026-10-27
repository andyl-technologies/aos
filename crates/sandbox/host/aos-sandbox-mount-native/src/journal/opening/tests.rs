//! Exercises full ordinary replay without supplying fixed Mount authority.

use aos_sandbox_model::OperationId;

use super::*;

#[test]
fn full_replay_preserves_non_mount_rows_and_their_idempotency_history() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("history.journal");
    let key = IdempotencyKey::new(b"ordinary-history".to_vec()).unwrap();
    let operation = OperationId::from_bytes([7; 16]);
    let transaction = JournalTransaction::new(
        [1; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                b"ordinary".to_vec(),
                b"value".to_vec(),
            ),
            JournalRecord::idempotency(&key, [2; 32], operation),
        ],
    )
    .unwrap();

    let (mut writer, _) = MountJournalV1::open(&path, JournalLimits::default()).unwrap();
    writer.commit(&transaction).unwrap();
    let next = writer.snapshot_sequence();
    drop(writer);

    let (mut writer, _) = MountJournalV1::open(&path, JournalLimits::default()).unwrap();

    assert_eq!(
        writer.get(RecordNamespace::DesiredState, b"ordinary"),
        Some(b"value".as_slice())
    );
    assert_eq!(
        writer.check_idempotency(&key, [2; 32]),
        IdempotencyOutcome::Replay(operation)
    );
    assert_eq!(
        writer.check_idempotency(&key, [3; 32]),
        IdempotencyOutcome::Conflict
    );
    assert_eq!(writer.snapshot_sequence(), next);
    assert_eq!(writer.all_records().count(), 2);
    assert!(MountSourceAcquisitionJournalAuthorityV2::claim(&mut writer).is_err());
}

#[test]
fn complete_commit_checksum_failure_is_not_repaired_as_an_incomplete_tail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("history.journal");
    let transaction = JournalTransaction::new(
        [1; 16],
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            b"ordinary".to_vec(),
            b"value".to_vec(),
        )],
    )
    .unwrap();

    let (mut writer, _) = MountJournalV1::open(&path, JournalLimits::default()).unwrap();
    writer.commit(&transaction).unwrap();
    drop(writer);
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &bytes).unwrap();

    assert!(matches!(
        MountJournalV1::open(&path, JournalLimits::default()),
        Err(JournalError::Mechanical(MechanicalError::ChecksumMismatch(
            _
        ))),
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

// The fixture opens a real protected file. It supplies no fixed Mount role,
// financial original or successful native observation.
fn retained_history(record: JournalRecord) -> (tempfile::TempDir, MountOpeningOriginalV1) {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    // Use the actual UID-owned executable-adjacent fixture directory.
    // The fixture gate omits root ancestry; final UID/mode, no-follow names,
    // flock and retained parser/post checks still use the native engine.
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("aos-mount-opening-")
        .tempdir_in(executable.parent().unwrap())
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = std::fs::metadata("/proc/self").unwrap().uid();
    let metadata = std::fs::metadata(directory.path()).unwrap();
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.path().join("history.journal"))
        .unwrap();
    let transaction = JournalTransaction::new([1; 16], vec![record]).unwrap();
    for frame in
        aos_sandbox_protocol::domain_ledger::transaction::encode_transaction(&transaction, 1)
            .unwrap()
    {
        file.write_all(&frame).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    drop(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("history.journal.lock"))
            .unwrap(),
    );

    let mut opening = MountOpeningOriginalV1::new();
    opening.prepare_fixture_once(
        directory.path(),
        "history.journal",
        JournalLimits::default(),
        uid,
        false,
        Disposition::Retained,
    );
    assert!(opening.failure().is_none(), "{:?}", opening.failure());
    (directory, opening)
}

fn append_external_byte(directory: &Path) {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(directory.join("history.journal"))
        .unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn captured_opening_refuses_real_prefix_drift_before_tail_or_transfer() {
    let (directory, mut opening) = retained_history(JournalRecord::put(
        RecordNamespace::DesiredState,
        b"ordinary".to_vec(),
        b"value".to_vec(),
    ));
    opening.replay_body_once();
    assert!(
        matches!(opening.replay, Some(Ok(()))),
        "{:?}",
        opening.failure()
    );

    append_external_byte(directory.path());
    assert!(opening.observe_prefix_post_once().is_err());

    assert!(opening.prefix_post.as_ref().unwrap().failure().is_some());
    assert!(matches!(opening.first, Some(ReplayFirst::PrefixPost)));
    assert!(opening.tail.is_none());
    assert!(opening.opened.is_none());
}

#[test]
fn captured_opening_keeps_semantic_cause_when_owed_prefix_post_also_refuses() {
    // Full ordinary replay always decodes capacity rows. An unselected Mount
    // row alone does not invoke a Mount authority's acquisition-family model.
    let (directory, mut opening) = retained_history(JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation,
        vec![255],
        vec![0],
    ));
    opening.replay_body_once();
    assert!(matches!(opening.replay, Some(Err(_))));
    assert!(opening.semantic.failure().is_some());
    assert!(matches!(
        opening.semantic.failure().unwrap().downcast_ref::<MechanicalError>(),
        Some(MechanicalError::MalformedRecord("capacity family header")),
    ));
    assert!(matches!(opening.first, Some(ReplayFirst::Semantic)));
    let first = opening.failure().unwrap() as *const dyn Error;

    append_external_byte(directory.path());
    assert!(opening.observe_prefix_post_once().is_err());

    assert!(opening.prefix_post.as_ref().unwrap().failure().is_some());
    assert!(std::ptr::eq(
        first,
        opening.failure().unwrap() as *const dyn Error
    ));
    assert!(matches!(opening.first, Some(ReplayFirst::Semantic)));
    assert!(opening.tail.is_none());
    assert!(opening.opened.is_none());
}

#[test]
fn existing_fixture_does_not_create_missing_journal_or_lock() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = std::fs::metadata(directory.path()).unwrap().uid();

    let opened = MountJournalV1::open_existing_protected_at_uid(
        directory.path(),
        "history.journal",
        JournalLimits::default(),
        uid,
    );

    assert!(opened.is_err());
    assert!(std::fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn existing_fixture_rejects_incomplete_tail_without_changing_bytes() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = std::fs::metadata(directory.path()).unwrap().uid();
    let (writer, _) = MountJournalV1::open_protected_at_uid(
        directory.path(),
        "history.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    drop(writer);
    append_external_byte(directory.path());
    let path = directory.path().join("history.journal");
    let before = std::fs::read(&path).unwrap();

    let reopened = MountJournalV1::open_existing_protected_at_uid(
        directory.path(),
        "history.journal",
        JournalLimits::default(),
        uid,
    );

    assert!(reopened.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
