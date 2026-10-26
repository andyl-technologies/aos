//! Exercises actual empty floor files and locks without a positive Source.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::*;

const LOCK: &str = "session-floor.journal.lock";
const COMPACT: &str = "session-floor.journal.compact.tmp";

fn fixture() -> (tempfile::TempDir, Journal, InitialFloorOriginal) {
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("initial-floor-")
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
    let (main, _) = opening.take_captured_opened().unwrap();
    let mut floor = InitialFloorOriginal::new();
    assert!(
        floor
            .quote_fixed_once(
                &main,
                replayed,
                Method46InitialServiceRoleV1::ControllerStorageClient,
                uid
            )
            .is_some()
    );
    // Only component fixtures select this private path. Production constructors
    // cannot select an arbitrary location, UID, Source or writer grant.
    floor.opening.recipe =
        ProtectedCapturedJournalRecipeV1::Method46InitialFloorFixture(directory.path().into(), uid);
    (directory, main, floor)
}

fn complete(floor: &mut InitialFloorOriginal, main: &Journal) {
    floor.prepare_once(main).unwrap();
    assert!(floor.quote_replay_once().is_some());
    floor.replay_once().unwrap();
    assert!(floor.quote_currentness_once().is_some());
    floor.begin_currentness_once(main).unwrap();
    assert!(floor.ready());
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn method46_initial_floor_requires_its_original_quote_before_creating_names() {
    let (directory, main, _) = fixture();
    let mut floor = InitialFloorOriginal::new();

    assert!(floor.prepare_once(&main).is_err());

    assert!(!directory.path().join(SIDECAR_NAME_V1).exists());
    assert!(!directory.path().join(LOCK).exists());
    assert!(floor.failure().is_some());
}

#[test]
fn method46_initial_floor_captures_empty_journal_and_exclusive_original_lock() {
    let (directory, main, mut floor) = fixture();

    complete(&mut floor, &main);

    assert_eq!(
        std::fs::metadata(directory.path().join(SIDECAR_NAME_V1))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(directory.path().join(LOCK))
            .unwrap()
            .len(),
        0
    );
    let foreign = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join(LOCK))
        .unwrap();
    assert!(
        rustix::fs::flock(
            &foreign,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        )
        .is_err()
    );
    assert!(floor.failure().is_none());
    floor.finish_after_owed(&main).unwrap();
    assert!(floor.failure().is_none());
    assert!(!floor.ready());
}

#[test]
fn method46_initial_floor_recovers_each_empty_creation_prefix_without_replacement() {
    use std::os::unix::fs::MetadataExt as _;

    for roster in 0..4 {
        let (directory, main, mut floor) = fixture();
        let mut identities = Vec::new();
        for (bit, name) in [SIDECAR_NAME_V1, LOCK].iter().enumerate() {
            if roster & (1 << bit) != 0 {
                let path = directory.path().join(name);
                write(&path, b"");
                identities.push((*name, std::fs::metadata(&path).unwrap().ino()));
            }
        }

        complete(&mut floor, &main);
        floor.finish_after_owed(&main).unwrap();

        for (name, inode) in identities {
            assert_eq!(
                std::fs::metadata(directory.path().join(name))
                    .unwrap()
                    .ino(),
                inode
            );
        }
        assert!(floor.failure().is_none());
    }
}

#[test]
fn method46_initial_floor_rejects_nonempty_unsafe_and_compaction_state_before_creation() {
    for case in 0..6 {
        let (directory, main, mut floor) = fixture();
        match case {
            0 => write(
                &directory.path().join(SIDECAR_NAME_V1),
                b"completed or conflicting floor",
            ),
            1 => write(&directory.path().join(LOCK), b"nonempty lock"),
            2 => write(&directory.path().join(COMPACT), b""),
            3 => {
                write(&directory.path().join(LOCK), b"");
                std::fs::set_permissions(
                    directory.path().join(LOCK),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            4 => {
                write(&directory.path().join("target"), b"");
                symlink("target", directory.path().join(LOCK)).unwrap();
            }
            5 => {
                write(&directory.path().join(LOCK), b"");
                std::fs::hard_link(directory.path().join(LOCK), directory.path().join("alias"))
                    .unwrap();
            }
            _ => unreachable!(),
        }

        assert!(floor.prepare_once(&main).is_err(), "case {case}");
        let _after = floor.finish_after_owed(&main);

        assert!(floor.failure().is_some());
        if case != 0 {
            assert!(!directory.path().join(SIDECAR_NAME_V1).exists());
        }
        if case == 0 {
            assert!(!directory.path().join(LOCK).exists());
        }
    }
}

#[test]
fn method46_initial_floor_foreign_flock_refuses_without_mutating_existing_names() {
    for existing_floor in [false, true] {
        let (directory, main, mut floor) = fixture();
        if existing_floor {
            write(&directory.path().join(SIDECAR_NAME_V1), b"");
        }
        write(&directory.path().join(LOCK), b"");
        let foreign = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join(LOCK))
            .unwrap();
        rustix::fs::flock(
            &foreign,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();

        assert!(floor.prepare_once(&main).is_err());
        let _after = floor.finish_after_owed(&main);

        assert!(floor.failure().is_some());
        if existing_floor {
            assert_eq!(
                std::fs::read(directory.path().join(SIDECAR_NAME_V1)).unwrap(),
                b""
            );
        } else {
            assert!(!directory.path().join(SIDECAR_NAME_V1).exists());
        }
        assert_eq!(std::fs::read(directory.path().join(LOCK)).unwrap(), b"");
    }
}

#[test]
fn method46_initial_floor_owed_post_rejects_changed_floor_and_missing_lock() {
    for replace_lock in [false, true] {
        let (directory, main, mut floor) = fixture();
        complete(&mut floor, &main);
        if replace_lock {
            std::fs::remove_file(directory.path().join(LOCK)).unwrap();
        } else {
            OpenOptions::new()
                .append(true)
                .open(directory.path().join(SIDECAR_NAME_V1))
                .unwrap()
                .write_all(b"changed floor")
                .unwrap();
        }

        assert!(floor.finish_after_owed(&main).is_err());

        assert!(floor.failure().is_some());
        assert!(floor.post.is_some());
        assert!(floor.currentness.after_failure().is_some());
    }
}

#[test]
fn method46_initial_floor_allows_own_directory_publication_but_preserves_main_metadata() {
    let (directory, main, mut floor) = fixture();
    complete(&mut floor, &main);
    write(
        &directory.path().join("session-floor.initial-intent"),
        &[7; 398],
    );

    floor.finish_after_owed(&main).unwrap();

    assert!(floor.failure().is_none());
}

#[test]
fn method46_initial_floor_changed_main_before_preparation_creates_nothing() {
    let (directory, main, mut floor) = fixture();
    OpenOptions::new()
        .append(true)
        .open(directory.path().join("journal"))
        .unwrap()
        .write_all(b"changed main")
        .unwrap();

    assert!(floor.prepare_once(&main).is_err());
    let _after = floor.finish_after_owed(&main);

    assert!(!directory.path().join(SIDECAR_NAME_V1).exists());
    assert!(!directory.path().join(LOCK).exists());
    assert!(floor.failure().is_some());
}
