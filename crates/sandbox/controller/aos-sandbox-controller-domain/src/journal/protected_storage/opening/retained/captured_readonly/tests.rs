//! Checks real opaque readonly acquisition, retained causes and owed posts.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

use super::*;

#[test]
fn failed_preparation_keeps_its_native_cause_across_reentry_and_replay() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    let mut original = ReadOnlyJournalOpenOriginalsV1::new();
    original.prepare_captured_once(&missing, "source.journal", JournalLimits::default(), 0, (0, 0));
    let first = original.failure().unwrap() as *const (dyn std::error::Error + 'static);
    assert!(original.failure().unwrap().downcast_ref::<JournalError>().is_some()
        || original.failure().unwrap().downcast_ref::<rustix::io::Errno>().is_some());
    assert!(original.captured_extent().is_none());
    assert!(original.native.replay_data_v1().report().is_none());
    assert!(original.returned.is_none());

    original.prepare_captured_once(Path::new("/"), "other.journal", JournalLimits::default(), 0, (0, 0));
    original.replay_captured_once();

    assert!(std::ptr::eq(first, original.failure().unwrap() as *const _));
    assert!(original.readback_mut().is_none());
    assert!(original.returned.is_none());
    assert!(original.native.replay_data_v1().report().is_none());
}

fn protected_fixture() -> tempfile::TempDir {
    // Shared /tmp ancestry deliberately refuses protected traversal. Use the
    // existing executable-adjacent fixture policy, with actual readonly opens.
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new().prefix("retained-readonly-")
        .tempdir_in(executable.parent().unwrap()).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, bytes) in [("source.journal", vec![0; aos_sandbox_journal::framing::HEADER_BYTES]),
                          ("source.journal.lock", Vec::new())] {
        std::fs::write(directory.path().join(name), bytes).unwrap();
        std::fs::set_permissions(directory.path().join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    directory
}

#[test]
fn malformed_same_file_replay_keeps_typed_parser_cause_and_independent_metadata_post() {
    let directory = protected_fixture();
    let metadata = std::fs::metadata(directory.path()).unwrap();
    let mut original = ReadOnlyJournalOpenOriginalsV1::new();
    original.prepare_captured_once(directory.path(), "source.journal", JournalLimits::default(),
        metadata.uid(), (metadata.dev(), metadata.ino()));
    assert!(original.captured_extent().is_some());

    original.replay_captured_once();

    assert!(matches!(original.failure().unwrap().downcast_ref::<aos_sandbox_journal::framing::FrameError>(),
        Some(aos_sandbox_journal::framing::FrameError::MalformedTransaction("invalid frame magic"))));
    let first = original.failure().unwrap() as *const dyn std::error::Error;
    assert!(matches!(original.returned, Some(Err(JournalError::ProtectedBoundary))));
    assert!(original.native.has_native_file_data_v1());
    let post = original.native.retained_prefix_post_v1().unwrap();
    assert!(post.metadata_result().is_ok());
    assert!(post.comparison_result().is_ok());
    assert!(original.native.retained_tail_failure_v1().is_none());
    assert!(original.readback_mut().is_none());

    // Reentry cannot replace the real parser cause or suppress the owed post.
    original.replay_captured_once();
    assert!(matches!(original.failure().unwrap().downcast_ref::<aos_sandbox_journal::framing::FrameError>(),
        Some(aos_sandbox_journal::framing::FrameError::MalformedTransaction("invalid frame magic"))));

    assert!(std::ptr::eq(first, original.failure().unwrap() as *const _));

    // An independently reached real name refusal cannot replace that parser
    // cause. This is a new observation, not an overwritten post or error DTO.
    std::fs::rename(directory.path().join("source.journal"),
        directory.path().join("old-source.journal")).unwrap();
    original.recheck_named_once();
    assert!(original.observe_named_currentness().unwrap().is_err());
    assert!(std::ptr::eq(first, original.failure().unwrap() as *const _));
    assert!(matches!(original.failure().unwrap().downcast_ref::<aos_sandbox_journal::framing::FrameError>(),
        Some(aos_sandbox_journal::framing::FrameError::MalformedTransaction("invalid frame magic"))));
}

#[test]
fn empty_captured_prefix_records_actual_geometry_before_replay() {
    let directory = protected_fixture();
    std::fs::write(directory.path().join("source.journal"), b"").unwrap();
    let metadata = std::fs::metadata(directory.path()).unwrap();
    let mut original = ReadOnlyJournalOpenOriginalsV1::new();

    original.prepare_captured_once(directory.path(), "source.journal", JournalLimits::default(),
        metadata.uid(), (metadata.dev(), metadata.ino()));
    let extent = original.captured_extent().unwrap();
    assert_eq!(extent.native_bytes, 0);
    assert_eq!(extent.source_checkpoint_rows, 0);
    assert_eq!(extent.declared_pending_record_bytes,
        JournalLimits::default().maximum_records_per_transaction * std::mem::size_of::<crate::journal::JournalRecord>());
    assert!(original.native.replay_data_v1().report().is_none());

    original.replay_captured_once();

    assert!(original.failure().is_none());
    assert_eq!(original.returned.as_ref().unwrap().as_ref().unwrap().truncated_bytes, 0);
    assert!(original.native.retained_prefix_post_v1().unwrap().metadata_result().is_ok());
    assert!(original.readback_mut().is_some());
}

#[test]
fn readonly_incomplete_tail_keeps_its_post_and_never_repairs_the_actual_file() {
    let directory = protected_fixture();
    std::fs::write(directory.path().join("source.journal"), b"tail").unwrap();
    let metadata = std::fs::metadata(directory.path()).unwrap();
    let mut original = ReadOnlyJournalOpenOriginalsV1::new();
    original.prepare_captured_once(directory.path(), "source.journal", JournalLimits::default(),
        metadata.uid(), (metadata.dev(), metadata.ino()));

    original.replay_captured_once();

    assert!(matches!(original.returned, Some(Err(JournalError::MalformedTransaction(
        "read-only journal has an uncommitted tail")))));
    let post = original.native.retained_prefix_post_v1().unwrap();
    assert_eq!(post.metadata_result().as_ref().unwrap().len(), 4);
    assert!(post.comparison_result().is_ok());
    assert_eq!(original.native.replay_data_v1().report().unwrap().0, 0);
    assert_eq!(std::fs::metadata(directory.path().join("source.journal")).unwrap().len(), 4);
    assert!(original.native.has_native_file_data_v1());
    assert!(original.readback_mut().is_none());
}

#[test]
fn captured_empty_input_excludes_later_growth_and_retains_the_refusing_post() {
    use std::io::Write as _;

    let directory = protected_fixture();
    std::fs::write(directory.path().join("source.journal"), b"").unwrap();
    let metadata = std::fs::metadata(directory.path()).unwrap();
    let mut original = ReadOnlyJournalOpenOriginalsV1::new();
    original.prepare_captured_once(directory.path(), "source.journal", JournalLimits::default(),
        metadata.uid(), (metadata.dev(), metadata.ino()));
    let mut appender = std::fs::OpenOptions::new().append(true)
        .open(directory.path().join("source.journal")).unwrap();
    appender.write_all(b"later bytes").unwrap();

    original.replay_captured_once();

    assert_eq!(original.native.replay_data_v1().report().unwrap().0, 0);
    assert!(original.native.replay_failure_v1().is_none());
    let post = original.native.retained_prefix_post_v1().unwrap();
    assert_eq!(post.metadata_result().as_ref().unwrap().len(), 11);
    assert!(matches!(post.comparison_result(), Err(JournalError::StaleAuthoritySnapshot)));
    assert!(original.native.has_native_file_data_v1());
    assert!(original.readback_mut().is_none());
}

#[test]
fn ordinary_empty_readonly_materializes_actual_readonly_owner_with_legacy_basename() {
    let directory = protected_fixture();
    std::fs::write(directory.path().join("source.journal"), b"").unwrap();
    let metadata = std::fs::metadata(directory.path()).unwrap();
    let mut original = ReadOnlyJournalOpenOriginalsV1::new();

    // This ordinary mechanical reader has no Root/Cache role or financial loan.
    original.open_once(directory.path(), "source.journal", JournalLimits::default(),
        metadata.uid(), (metadata.dev(), metadata.ino()));

    assert!(original.failure().is_none());
    assert!(original.extent.is_none());
    assert_eq!(original.returned.as_ref().unwrap().as_ref().unwrap().committed_transactions, 0);
    let readback = original.readback_mut().unwrap();
    assert_eq!(readback.journal.native.path(), &PathBuf::from("source.journal"));
    assert!(readback.journal.native.ordinary_readonly_held_v1().unwrap().is_read_only_v1());
    assert!(readback.journal.native.state().is_empty());
}
