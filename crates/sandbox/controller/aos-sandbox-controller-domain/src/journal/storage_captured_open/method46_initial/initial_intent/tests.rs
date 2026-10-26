//! Exercises real native durability mechanics without manufacturing a Source.

use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::*;

fn fixture() -> (tempfile::TempDir, Journal, InitialIntentOriginal) {
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("initial-intent-")
        .tempdir_in(executable.parent().unwrap())
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let mut opening = ProtectedWriterOpenOriginalsV1::new();
    opening.prepare_captured_for_uid_once(
        directory.path(),
        "journal",
        JournalLimits::default(),
        uid,
        true,
    );
    assert!(opening.failure().is_none(), "{:?}", opening.failure());
    opening.replay_prepared_once();
    let replayed = opening.captured_replay_file_identity_data_v1().unwrap();
    let (journal, _) = opening.take_captured_opened().unwrap();
    let mut original = InitialIntentOriginal::new();
    original.intent_uid = uid;
    let demand = original.quote_once(&journal, replayed).unwrap();
    assert_eq!(demand.get(D::StorageBytes), INTENT_BYTES as u64);
    assert_eq!(demand.get(D::PublicationStagingBytes), INTENT_BYTES as u64);
    (directory, journal, original)
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn method46_initial_intent_requires_payment_before_native_capture() {
    let (directory, journal, _) = fixture();
    let mut original = InitialIntentOriginal::new();

    assert!(original.capture_once(&journal).is_err());

    assert!(original.before.iter().all(|name| name.open.is_none()));
    assert!(!directory.path().join(STAGE).exists());
    assert!(!directory.path().join(FINAL).exists());
}

#[test]
fn method46_initial_intent_new_publication_keeps_original_sync_and_name_results() {
    let (directory, journal, mut original) = fixture();
    let bytes = [7; INTENT_BYTES];
    original.capture_once(&journal).unwrap();
    assert_eq!(original.captured_intent_data().unwrap(), None);
    assert!(!original.durable_ready());

    original.publish_once(&journal, bytes).unwrap();

    assert_eq!(std::fs::read(directory.path().join(FINAL)).unwrap(), bytes);
    assert!(!directory.path().join(STAGE).exists());
    assert!(matches!(original.file_sync, Some(Ok(()))));
    assert!(matches!(original.rename, Some(Ok(()))));
    assert!(matches!(original.directory_sync, Some(Ok(()))));
    assert!(original.durable_ready());
    assert!(matches!(original.post, Some(Ok(()))));
    assert!(original.failure().is_none());
    original.finish_after_owed(&journal).unwrap();
    assert!(original.publish_once(&journal, [8; INTENT_BYTES]).is_err());
    assert!(!original.durable_ready());
    assert_eq!(std::fs::read(directory.path().join(FINAL)).unwrap(), bytes);
    assert!(matches!(original.operation, Some(Ok(()))));
}

#[test]
fn method46_initial_intent_resumes_only_exact_partial_prefixes() {
    let bytes = [7; INTENT_BYTES];
    for length in [0, 1, 199, INTENT_BYTES - 1, INTENT_BYTES] {
        let (directory, journal, mut original) = fixture();
        write(&directory.path().join(STAGE), &bytes[..length]);
        original.capture_once(&journal).unwrap();

        original.publish_once(&journal, bytes).unwrap();

        assert_eq!(std::fs::read(directory.path().join(FINAL)).unwrap(), bytes);
        assert!(!directory.path().join(STAGE).exists());
        assert!(matches!(original.write, Some(Ok(written)) if written == INTENT_BYTES - length));
        assert!(original.failure().is_none());
    }
}

#[test]
fn method46_initial_intent_recovery_resyncs_the_actual_existing_exact_file() {
    let (directory, journal, mut original) = fixture();
    let bytes = [7; INTENT_BYTES];
    write(&directory.path().join(FINAL), &bytes);
    let inode = std::fs::metadata(directory.path().join(FINAL))
        .unwrap()
        .ino();
    original.capture_once(&journal).unwrap();
    assert_eq!(original.captured_intent_data().unwrap(), Some(bytes));
    assert!(!original.durable_ready());

    original.publish_once(&journal, bytes).unwrap();

    assert!(original.durable_ready());
    assert!(original.stage_open.is_none());
    assert!(original.write.is_none());
    assert!(original.rename.is_none());
    assert!(matches!(original.file_sync, Some(Ok(()))));
    assert_eq!(
        std::fs::metadata(directory.path().join(FINAL))
            .unwrap()
            .ino(),
        inode
    );
    assert!(original.failure().is_none());
}

#[test]
fn method46_initial_intent_conflicts_are_preserved_with_independent_posts() {
    for name in [FINAL, STAGE] {
        let (directory, journal, mut original) = fixture();
        let conflict = if name == FINAL {
            vec![8; INTENT_BYTES]
        } else {
            vec![8; 37]
        };
        write(&directory.path().join(name), &conflict);
        original.capture_once(&journal).unwrap();

        assert!(original.publish_once(&journal, [7; INTENT_BYTES]).is_err());

        assert_eq!(
            std::fs::read(directory.path().join(name)).unwrap(),
            conflict
        );
        assert!(original.stage_open.is_none());
        assert!(original.write.is_none());
        assert!(!original.durable_ready());
        assert!(matches!(original.directory_sync, Some(Ok(()))));
        assert!(original.after.iter().all(|name| name.open.is_some()));
        assert!(original.failure().is_some());
    }
}

#[test]
fn method46_initial_intent_refuses_unsafe_or_completed_state_without_mutation() {
    for case in 0..7 {
        let (directory, journal, mut original) = fixture();
        let final_path = directory.path().join(FINAL);
        match case {
            0 => {
                write(&final_path, &[7; INTENT_BYTES]);
                write(&directory.path().join(STAGE), b"");
            }
            1 => {
                write(&final_path, &[7; INTENT_BYTES - 1]);
            }
            2 => {
                write(&directory.path().join(STAGE), &[7; INTENT_BYTES + 1]);
            }
            3 => {
                write(&final_path, &[7; INTENT_BYTES]);
                std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            4 => {
                write(&final_path, &[7; INTENT_BYTES]);
                std::fs::hard_link(&final_path, directory.path().join("alias")).unwrap();
            }
            5 => {
                write(&directory.path().join("target"), &[7; INTENT_BYTES]);
                symlink("target", &final_path).unwrap();
            }
            6 => {
                write(
                    &directory.path().join(SIDECAR_NAME_V1),
                    b"completed-or-conflicting-floor",
                );
            }
            _ => unreachable!(),
        }

        assert!(original.capture_once(&journal).is_err(), "case {case}");
        let _post = original.finish_after_owed(&journal);

        assert!(original.write.is_none());
        assert!(original.rename.is_none());
        assert!(original.after.iter().all(|name| name.open.is_some()));
        assert!(original.failure().is_some());
        if case == 6 {
            assert_eq!(
                std::fs::read(directory.path().join(SIDECAR_NAME_V1)).unwrap(),
                b"completed-or-conflicting-floor"
            );
        }
    }
}

#[test]
fn method46_initial_intent_replaced_stage_is_never_written_or_unlinked() {
    let (directory, journal, mut original) = fixture();
    write(&directory.path().join(STAGE), &[7; 23]);
    original.capture_once(&journal).unwrap();
    std::fs::rename(
        directory.path().join(STAGE),
        directory.path().join("retained-stage"),
    )
    .unwrap();
    write(&directory.path().join(STAGE), &[7; 23]);

    assert!(original.publish_once(&journal, [7; INTENT_BYTES]).is_err());

    assert!(original.write.is_none());
    assert!(original.rename.is_none());
    assert_eq!(
        std::fs::read(directory.path().join(STAGE)).unwrap(),
        [7; 23]
    );
    assert_eq!(
        std::fs::read(directory.path().join("retained-stage")).unwrap(),
        [7; 23]
    );
    assert!(original.after.iter().all(|name| name.open.is_some()));
}

#[test]
fn method46_initial_intent_publish_never_replaces_a_racing_final_name() {
    let (directory, journal, mut original) = fixture();
    original.capture_once(&journal).unwrap();
    write(&directory.path().join(FINAL), &[8; INTENT_BYTES]);

    assert!(original.publish_once(&journal, [7; INTENT_BYTES]).is_err());

    assert!(matches!(
        original.rename,
        Some(Err(rustix::io::Errno::EXIST))
    ));
    assert_eq!(
        std::fs::read(directory.path().join(FINAL)).unwrap(),
        [8; INTENT_BYTES]
    );
    assert_eq!(
        std::fs::read(directory.path().join(STAGE)).unwrap(),
        [7; INTENT_BYTES]
    );
    assert!(original.after.iter().all(|name| name.open.is_some()));
}

#[test]
fn method46_initial_intent_main_and_floor_changes_close_the_native_publication() {
    for mutate_floor in [false, true] {
        let (directory, journal, mut original) = fixture();
        original.capture_once(&journal).unwrap();
        if mutate_floor {
            write(&directory.path().join(SIDECAR_NAME_V1), b"unexpected floor");
        } else {
            std::fs::OpenOptions::new()
                .append(true)
                .open(directory.path().join("journal"))
                .unwrap()
                .write_all(b"changed main")
                .unwrap();
        }

        assert!(original.publish_once(&journal, [7; INTENT_BYTES]).is_err());

        assert!(matches!(original.operation, Some(Ok(()))));
        assert!(matches!(original.post, Some(Err(_))));
        assert!(original.failure().is_some());
    }
}
