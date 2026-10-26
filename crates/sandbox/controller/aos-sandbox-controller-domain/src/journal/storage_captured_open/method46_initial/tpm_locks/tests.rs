//! Checks real lock custody and failed-prefix retention without a Source grant.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;

use super::*;

fn fixture() -> (tempfile::TempDir, [Journal; 2], [FileIdentity; 2]) {
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("initial-tpm-locks-")
        .tempdir_in(executable.parent().unwrap())
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let open = |name| {
        let mut original = ProtectedWriterOpenOriginalsV1::new();
        original.prepare_captured_for_uid_once(
            directory.path(),
            name,
            JournalLimits::default(),
            uid,
            true,
        );
        assert!(original.failure().is_none(), "{:?}", original.failure());
        original.replay_prepared_once();
        let replayed = original.captured_replay_file_identity_data_v1().unwrap();
        (original.take_captured_opened().unwrap().0, replayed)
    };
    let (main, main_replayed) = open("journal");
    let (floor, floor_replayed) = open("session-floor.journal");
    (directory, [main, floor], [main_replayed, floor_replayed])
}

fn capture(journals: &[Journal; 2], replayed: [FileIdentity; 2]) -> InitialTpmLocksOriginal {
    let mut original = InitialTpmLocksOriginal::new();
    let pair = [&journals[0], &journals[1]];
    let demand = original.quote_once(pair, replayed).unwrap();
    assert!(demand.get(D::OpenFiles) >= 2);
    original.capture_once(pair).unwrap();
    original
}

fn foreign_lock(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

#[test]
fn method46_initial_tpm_lock_pair_requires_its_original_quote() {
    let (_directory, journals, _) = fixture();
    let mut original = InitialTpmLocksOriginal::new();

    assert!(original.capture_once([&journals[0], &journals[1]]).is_err());

    assert!(
        original
            .locks
            .iter()
            .all(|lock| lock.file.is_none() && lock.duplicate.is_none())
    );
    assert!(original.before.iter().all(Option::is_none));
    assert!(original.borrowed_descriptors().is_none());
}

#[test]
fn method46_initial_tpm_lock_pair_preserves_both_real_flocks_after_writer_drop() {
    let (directory, journals, replayed) = fixture();
    let mut original = capture(&journals, replayed);
    let identities = original.captured_identities_data().unwrap();
    assert_ne!(
        (identities[0].0, identities[0].1),
        (identities[1].0, identities[1].1)
    );
    assert_eq!(identities[0].2, identities[1].2);

    original
        .finish_after_owed([&journals[0], &journals[1]])
        .unwrap();
    assert!(original.borrowed_descriptors().is_none());
    assert!(original.locks.iter().all(|lock| {
        lock.samples
            .iter()
            .all(|sample| matches!(sample.result, Some(Ok(()))))
    }));
    drop(journals);

    let foreign = [
        foreign_lock(&directory.path().join("journal.lock")),
        foreign_lock(&directory.path().join("session-floor.journal.lock")),
    ];
    for file in &foreign {
        assert!(
            rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err()
        );
    }
    drop(original);
    for file in &foreign {
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    }
}

#[test]
fn method46_initial_tpm_lock_pair_rejects_aliases_without_discarding_duplicates() {
    let (_directory, journals, replayed) = fixture();
    let mut original = InitialTpmLocksOriginal::new();
    let pair = [&journals[0], &journals[0]];
    original.quote_once(pair, [replayed[0]; 2]).unwrap();

    assert!(original.capture_once(pair).is_err());
    assert!(original.finish_after_owed(pair).is_err());

    assert!(original.locks.iter().all(|lock| lock.file.is_some()));
    assert!(
        original
            .after
            .iter()
            .all(|result| matches!(result, Some(Ok(()))))
    );
    assert!(original.borrowed_descriptors().is_none());
}

#[test]
fn method46_initial_tpm_lock_pair_checks_the_second_before_after_first_refusal() {
    let (directory, journals, replayed) = fixture();
    let pair = [&journals[0], &journals[1]];
    let mut original = InitialTpmLocksOriginal::new();
    original.quote_once(pair, replayed).unwrap();
    std::fs::remove_file(directory.path().join("journal.lock")).unwrap();

    assert!(original.capture_once(pair).is_err());
    assert!(original.finish_after_owed(pair).is_err());

    assert!(matches!(original.before[0], Some(Err(_))));
    assert!(matches!(original.before[1], Some(Ok(()))));
    assert!(original.after.iter().all(Option::is_some));
    assert!(original.locks.iter().all(|lock| lock.file.is_none()));
}

#[test]
fn method46_initial_tpm_lock_pair_preserves_custody_and_both_posts_after_name_loss() {
    let (directory, journals, replayed) = fixture();
    let mut original = capture(&journals, replayed);
    let descriptors = original
        .borrowed_descriptors()
        .unwrap()
        .map(|fd| fd.as_raw_fd());
    std::fs::remove_file(directory.path().join("session-floor.journal.lock")).unwrap();

    assert!(
        original
            .finish_after_owed([&journals[0], &journals[1]])
            .is_err()
    );

    // Both strict intervals also observe the changed shared directory metadata.
    assert!(
        original
            .after
            .iter()
            .all(|result| matches!(result, Some(Err(_))))
    );
    assert_eq!(
        original
            .locks
            .each_ref()
            .map(|lock| lock.file.as_ref().unwrap().as_raw_fd()),
        descriptors
    );
    assert!(original.locks[1].samples[1].metadata.is_some());
    assert!(original.borrowed_descriptors().is_none());
}

#[test]
fn method46_initial_tpm_lock_pair_rejects_changes_to_either_journal() {
    for (index, name) in ["journal", "session-floor.journal"].iter().enumerate() {
        let (directory, journals, replayed) = fixture();
        let mut original = capture(&journals, replayed);
        OpenOptions::new()
            .append(true)
            .open(directory.path().join(name))
            .unwrap()
            .write_all(b"changed")
            .unwrap();

        assert!(
            original
                .finish_after_owed([&journals[0], &journals[1]])
                .is_err()
        );

        assert!(matches!(original.after[index], Some(Err(_))));
        assert!(original.after.iter().all(Option::is_some));
        assert!(original.locks.iter().all(|lock| lock.file.is_some()));
    }
}

#[test]
fn method46_initial_tpm_lock_pair_reentry_preserves_originals_and_owed_posts() {
    let (_directory, journals, replayed) = fixture();
    let mut original = capture(&journals, replayed);
    let descriptors = original
        .borrowed_descriptors()
        .unwrap()
        .map(|fd| fd.as_raw_fd());

    assert!(original.capture_once([&journals[0], &journals[1]]).is_err());
    assert!(
        original
            .finish_after_owed([&journals[0], &journals[1]])
            .is_err()
    );

    assert_eq!(
        original
            .locks
            .each_ref()
            .map(|lock| lock.file.as_ref().unwrap().as_raw_fd()),
        descriptors
    );
    assert!(original.after.iter().all(Option::is_some));
    assert!(original.borrowed_descriptors().is_none());
}
