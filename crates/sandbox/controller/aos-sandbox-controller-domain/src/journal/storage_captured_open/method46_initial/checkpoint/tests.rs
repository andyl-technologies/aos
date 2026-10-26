//! Exercises native checkpoint-stage capture without a positive Source or TPM.

use std::io::Cursor;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use aos_sandbox_journal::framing::{FrameKind, read_frame_retained};
use aos_sandbox_journal::record::RecordHeader;
use aos_sandbox_journal::transaction::{NativePendingTransaction, decode_begin_count};

use super::*;

fn fixture() -> (
    tempfile::TempDir,
    Journal,
    FileIdentity,
    InitialCheckpointOriginal,
) {
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("initial-checkpoint-")
        .tempdir_in(executable.parent().unwrap())
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut opening = ProtectedWriterOpenOriginalsV1::new();
    opening.prepare_captured_for_uid_once(
        directory.path(),
        "journal",
        JournalLimits::default(),
        rustix::process::geteuid().as_raw(),
        true,
    );
    assert!(opening.failure().is_none(), "{:?}", opening.failure());
    opening.replay_prepared_once();
    let replayed = opening.captured_replay_file_identity_data_v1().unwrap();
    let (main, _) = opening.take_captured_opened().unwrap();
    let mut original = InitialCheckpointOriginal::new();
    assert!(original.quote_once(&main, replayed).is_some());
    (directory, main, replayed, original)
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn method46_initial_checkpoint_stage_requires_payment_before_encoding_or_io() {
    let (directory, main, _, _) = fixture();
    let mut original = InitialCheckpointOriginal::new();

    assert!(
        original
            .capture_once(&main, [7; CHECKPOINT_BYTES_V1])
            .is_err()
    );

    assert!(original.encoded.is_none());
    assert!(original.open.is_none());
    assert!(!directory.path().join(STAGE).exists());
    assert!(original.failure().is_some());
}

#[test]
fn method46_initial_checkpoint_stage_uses_full_canonical_transaction_without_writes() {
    let (directory, main, _, mut original) = fixture();
    let checkpoint = [7; CHECKPOINT_BYTES_V1];

    original.capture_once(&main, checkpoint).unwrap();

    assert!(original.ready());
    assert!(!directory.path().join(STAGE).exists());
    let expected = original.expected.unwrap();
    assert_eq!(expected.len(), 429);
    let mut input = Cursor::new(expected);
    let (begin, after_begin) = read_frame_retained(&mut input, 0, 1024, None)
        .unwrap()
        .unwrap();
    assert_eq!(begin.kind, FrameKind::Begin);
    assert_eq!(begin.sequence, 1);
    // Independent digest vector preserves all UUID-width bits unchanged.
    assert_eq!(
        begin.transaction_id,
        [
            0x96, 0xac, 0x1d, 0x2e, 0x5b, 0x47, 0xa4, 0x6a, 0x2a, 0x35, 0x96, 0x1f, 0xc7, 0xfd,
            0xf2, 0x83
        ]
    );
    let mut transaction = NativePendingTransaction::begin(
        &begin,
        decode_begin_count(&begin.payload, 1).unwrap(),
        after_begin,
        after_begin,
    )
    .unwrap();

    let (record, record_bytes) = read_frame_retained(&mut input, after_begin, 1024, None)
        .unwrap()
        .unwrap();
    assert_eq!(record.kind, FrameKind::Record);
    assert_eq!(record.sequence, 2);
    transaction.observe_record(&record, 0).unwrap();
    let header = RecordHeader::read(&record.payload).unwrap();
    assert_eq!(header.namespace_byte(), 47);
    let fields = header.decode_fields(32, 1024).unwrap();
    assert_eq!(fields.key, b"checkpoint");
    assert_eq!(fields.value, Some(checkpoint.as_slice()));

    let after_record = after_begin + record_bytes;
    let (commit, commit_bytes) = read_frame_retained(&mut input, after_record, 1024, None)
        .unwrap()
        .unwrap();
    assert_eq!(commit.kind, FrameKind::Commit);
    assert_eq!(commit.sequence, 3);
    transaction.validate_commit(&commit, 1).unwrap();
    let end = after_record + commit_bytes;
    assert_eq!(end, 429);
    assert!(
        read_frame_retained(&mut input, end, 1024, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn method46_initial_checkpoint_stage_accepts_only_matching_partial_prefixes() {
    let (_reference_directory, reference_main, _, mut reference) = fixture();
    reference
        .capture_once(&reference_main, [7; CHECKPOINT_BYTES_V1])
        .unwrap();
    let expected = reference.expected.unwrap();

    for length in [0, 1, 75, 76, 200, 428, 429] {
        let (directory, main, _, mut original) = fixture();
        let path = directory.path().join(STAGE);
        write(&path, &expected[..length]);
        let before = std::fs::metadata(&path).unwrap();

        original
            .capture_once(&main, [7; CHECKPOINT_BYTES_V1])
            .unwrap();

        assert!(original.ready());
        assert_eq!(original.bytes.as_deref(), Some(&expected[..length]));
        assert_eq!(std::fs::read(&path).unwrap(), expected[..length]);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), before.ino());
        assert!(matches!(original.after, Some(Ok(()))));
    }
}

#[test]
fn method46_initial_checkpoint_stage_conflicts_are_preserved_with_native_after() {
    for case in 0..6 {
        let (directory, main, _, mut original) = fixture();
        let path = directory.path().join(STAGE);
        match case {
            0 => write(&path, &[8; 23]),
            1 => write(&path, &[8; FRAMED_BYTES + 1]),
            2 => {
                write(&path, b"");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            3 => {
                write(&directory.path().join("target"), b"");
                symlink("target", &path).unwrap();
            }
            4 => {
                write(&path, b"");
                std::fs::hard_link(&path, directory.path().join("alias")).unwrap();
            }
            5 => std::fs::create_dir(&path).unwrap(),
            _ => unreachable!(),
        }
        let before = std::fs::symlink_metadata(&path).unwrap();

        assert!(
            original
                .capture_once(&main, [7; CHECKPOINT_BYTES_V1])
                .is_err(),
            "case {case}"
        );

        assert!(original.failure().is_some());
        assert!(!original.ready());
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().ino(),
            before.ino()
        );
        if case <= 1 {
            assert_eq!(std::fs::metadata(&path).unwrap().len(), before.len());
        }
        assert!(matches!(original.after, Some(Ok(()))));
        assert!(original.after.is_some());
    }
}

#[test]
fn method46_initial_checkpoint_stage_changed_main_refuses_before_stage_open() {
    let (directory, main, _, mut original) = fixture();
    write(&directory.path().join("journal"), b"changed main");

    assert!(
        original
            .capture_once(&main, [7; CHECKPOINT_BYTES_V1])
            .is_err()
    );

    assert!(original.open.is_none());
    assert!(original.encoded.is_none());
    assert!(original.after.is_some());
    let cause = original.failure().unwrap() as *const dyn Error as *const ();
    assert!(
        original
            .capture_once(&main, [8; CHECKPOINT_BYTES_V1])
            .is_err()
    );
    assert_eq!(
        original.failure().unwrap() as *const dyn Error as *const (),
        cause
    );
    assert!(!directory.path().join(STAGE).exists());
}
