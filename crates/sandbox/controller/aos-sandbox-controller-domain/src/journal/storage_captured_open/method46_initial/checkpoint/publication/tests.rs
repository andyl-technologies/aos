//! Exercises actual publication, writer locks and adverse name changes.
//!
//! These mechanical fixtures manufacture neither a positive Source nor a TPM
//! observation. They retain real protected journals and use the normal canonical
//! reader to verify installed transaction DATA after publication.

use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt as _;

use super::*;

fn fixture(
    prefix: Option<&[u8]>,
) -> (
    tempfile::TempDir,
    Journal,
    Journal,
    FileIdentity,
    InitialCheckpointOriginal,
) {
    let (directory, main, replayed, mut checkpoint) = super::super::tests::fixture();
    if let Some(prefix) = prefix {
        write(&directory.path().join(STAGE), prefix);
    }
    let mut opening = ProtectedWriterOpenOriginalsV1::new();
    opening.prepare_captured_for_uid_once(
        directory.path(),
        SIDECAR_NAME_V1,
        JournalLimits::default(),
        rustix::process::geteuid().as_raw(),
        true,
    );
    assert!(opening.failure().is_none(), "{:?}", opening.failure());
    opening.replay_prepared_once();
    let empty = opening.captured_replay_file_identity_data_v1().unwrap();
    let (floor, _) = opening.take_captured_opened().unwrap();
    checkpoint
        .capture_once(&main, [7; CHECKPOINT_BYTES_V1])
        .unwrap();
    assert!(checkpoint.publication.quote_once(&main, replayed).is_some());
    (directory, main, floor, empty, checkpoint)
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn prepare(
    checkpoint: &mut InitialCheckpointOriginal,
    main: &Journal,
    empty: FileIdentity,
) -> Result<(), JournalError> {
    let captured = checkpoint.metadata[1]
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(FileIdentity::from_metadata_data_v1);
    checkpoint.publication.prepare_once(
        main,
        empty,
        checkpoint.expected.as_ref().unwrap(),
        captured,
        checkpoint.bytes.as_deref(),
    )
}

fn finish(checkpoint: &mut InitialCheckpointOriginal, main: &Journal) -> Result<(), JournalError> {
    let sync = checkpoint.publication.sync_after_owed(main);
    let after = checkpoint
        .publication
        .finish_after_owed(main, checkpoint.expected.as_ref().unwrap());
    sync.and(after)
}

fn install(checkpoint: &mut InitialCheckpointOriginal, main: &Journal, empty: FileIdentity) {
    prepare(checkpoint, main, empty).unwrap();
    checkpoint
        .publication
        .validate_once(main, checkpoint.expected.as_ref().unwrap())
        .unwrap();
    checkpoint.publication.exchange_once(main).unwrap();
    finish(checkpoint, main).unwrap();
}

#[test]
fn method46_initial_checkpoint_publication_requires_its_original_quote() {
    let (directory, main, _floor, empty, checkpoint) = fixture(None);
    let mut publication = InitialCheckpointPublicationOriginal::new();

    assert!(
        publication
            .prepare_once(
                &main,
                empty,
                checkpoint.expected.as_ref().unwrap(),
                None,
                None
            )
            .is_err()
    );

    assert!(publication.stage.is_none());
    assert!(publication.before.iter().all(|name| name.open.is_none()));
    assert!(!directory.path().join(STAGE).exists());
}

#[test]
fn method46_initial_checkpoint_publication_preserves_displaced_inode_and_both_real_locks() {
    let (directory, main, floor, empty, mut checkpoint) = fixture(None);
    let expected = checkpoint.expected.unwrap();

    install(&mut checkpoint, &main, empty);

    assert_eq!(
        std::fs::read(directory.path().join(SIDECAR_NAME_V1)).unwrap(),
        expected
    );
    assert_eq!(std::fs::read(directory.path().join(STAGE)).unwrap(), b"");
    assert_eq!(
        std::fs::metadata(directory.path().join(STAGE))
            .unwrap()
            .ino(),
        empty.physical_pair().1
    );
    assert!(matches!(checkpoint.publication.file_sync, Some(Ok(()))));
    assert!(matches!(
        checkpoint.publication.directory_sync,
        Some(Ok(()))
    ));
    for name in ["journal.lock", "session-floor.journal.lock"] {
        let foreign = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join(name))
            .unwrap();
        assert!(
            rustix::fs::flock(
                &foreign,
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            )
            .is_err()
        );
    }
    // A new ordinary read uses the installed file after the actual old floor
    // writer ends. No prospective map or caller-supplied replay is adopted.
    drop(floor);
    let (readback, _) = Journal::open_read_only_protected_at_uid_for_test(
        directory.path(),
        SIDECAR_NAME_V1,
        JournalLimits::default(),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    readback.check_named_currentness_at_uid_for_test().unwrap();
    let (readback, _witness) = readback.into_parts();
    assert_eq!(readback.snapshot_sequence(), 4);
    assert_eq!(
        readback.get(RecordNamespace::BrokerSessionTraffic, b"checkpoint"),
        Some([7; CHECKPOINT_BYTES_V1].as_slice())
    );
    assert!(checkpoint.publication.failure().is_none());
}

#[test]
fn method46_initial_checkpoint_publication_resumes_exact_prefix_and_resyncs_complete_stage() {
    let (_reference_directory, reference_main, _reference_floor, _, reference) = fixture(None);
    let expected = reference.expected.unwrap();
    drop(reference_main);
    for length in [0, 1, 76, 200, 428, 429] {
        let (directory, main, _floor, empty, mut checkpoint) = fixture(Some(&expected[..length]));
        let inode = std::fs::metadata(directory.path().join(STAGE))
            .unwrap()
            .ino();

        install(&mut checkpoint, &main, empty);

        assert_eq!(
            std::fs::metadata(directory.path().join(SIDECAR_NAME_V1))
                .unwrap()
                .ino(),
            inode
        );
        assert_eq!(
            std::fs::read(directory.path().join(SIDECAR_NAME_V1)).unwrap(),
            expected
        );
        assert!(matches!(checkpoint.publication.file_sync, Some(Ok(()))));
        if length == 429 {
            assert!(checkpoint.publication.write.is_none());
        } else {
            assert!(
                matches!(checkpoint.publication.write, Some(Ok(bytes)) if bytes == 429 - length)
            );
        }
    }
}

#[test]
fn method46_initial_checkpoint_publication_rechecks_capture_without_overwriting_changed_stage() {
    let (directory, main, _floor, empty, mut checkpoint) = fixture(Some(b""));
    std::fs::rename(
        directory.path().join(STAGE),
        directory.path().join("captured-stage"),
    )
    .unwrap();
    write(&directory.path().join(STAGE), b"foreign prefix");

    assert!(prepare(&mut checkpoint, &main, empty).is_err());
    assert!(finish(&mut checkpoint, &main).is_err());

    assert_eq!(
        std::fs::read(directory.path().join(STAGE)).unwrap(),
        b"foreign prefix"
    );
    assert_eq!(
        std::fs::read(directory.path().join("captured-stage")).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(directory.path().join(SIDECAR_NAME_V1)).unwrap(),
        b""
    );
    assert!(checkpoint.publication.stage.is_none());
    assert!(
        checkpoint
            .publication
            .after
            .iter()
            .all(|name| name.open.is_some())
    );
    assert!(matches!(
        checkpoint.publication.directory_sync,
        Some(Ok(()))
    ));
}

#[test]
fn method46_initial_checkpoint_publication_rechecks_main_after_stage_fsync_before_exchange() {
    let (directory, main, _floor, empty, mut checkpoint) = fixture(None);
    prepare(&mut checkpoint, &main, empty).unwrap();
    write(
        &directory.path().join("journal"),
        b"changed main after disk wait",
    );

    assert!(
        checkpoint
            .publication
            .validate_once(&main, checkpoint.expected.as_ref().unwrap())
            .is_err()
    );
    assert!(checkpoint.publication.exchange_once(&main).is_err());
    assert!(finish(&mut checkpoint, &main).is_err());

    assert!(checkpoint.publication.exchange.is_none());
    assert_eq!(
        std::fs::read(directory.path().join(SIDECAR_NAME_V1)).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(directory.path().join(STAGE)).unwrap(),
        checkpoint.expected.unwrap()
    );
    assert!(
        checkpoint
            .publication
            .after
            .iter()
            .all(|name| name.open.is_some())
    );
}

#[test]
fn method46_initial_checkpoint_publication_rechecks_both_names_after_stage_fsync() {
    for name in [STAGE, SIDECAR_NAME_V1] {
        let (directory, main, _floor, empty, mut checkpoint) = fixture(None);
        prepare(&mut checkpoint, &main, empty).unwrap();
        std::fs::rename(
            directory.path().join(name),
            directory.path().join("prepared-original"),
        )
        .unwrap();
        write(&directory.path().join(name), b"foreign name");

        assert!(
            checkpoint
                .publication
                .validate_once(&main, checkpoint.expected.as_ref().unwrap())
                .is_err()
        );
        assert!(finish(&mut checkpoint, &main).is_err());

        assert_eq!(
            std::fs::read(directory.path().join(name)).unwrap(),
            b"foreign name"
        );
        assert!(directory.path().join("prepared-original").exists());
        assert!(checkpoint.publication.exchange.is_none());
        assert!(
            checkpoint
                .publication
                .after
                .iter()
                .all(|name| name.open.is_some())
        );
    }
}

#[test]
fn method46_initial_checkpoint_publication_exchange_races_preserve_foreign_files_and_fence_success()
{
    for name in [STAGE, SIDECAR_NAME_V1] {
        let (directory, main, _floor, empty, mut checkpoint) = fixture(None);
        prepare(&mut checkpoint, &main, empty).unwrap();
        checkpoint
            .publication
            .validate_once(&main, checkpoint.expected.as_ref().unwrap())
            .unwrap();
        std::fs::rename(
            directory.path().join(name),
            directory.path().join("validated-original"),
        )
        .unwrap();
        write(&directory.path().join(name), b"foreign file at exchange");

        checkpoint.publication.exchange_once(&main).unwrap();
        assert!(finish(&mut checkpoint, &main).is_err());

        let displaced_name = if name == STAGE {
            SIDECAR_NAME_V1
        } else {
            STAGE
        };
        assert_eq!(
            std::fs::read(directory.path().join(displaced_name)).unwrap(),
            b"foreign file at exchange"
        );
        assert!(directory.path().join("validated-original").exists());
        assert!(checkpoint.publication.failure().is_some());
        assert!(matches!(
            checkpoint.publication.directory_sync,
            Some(Ok(()))
        ));
    }
}

#[test]
fn method46_initial_checkpoint_publication_failed_exchange_keeps_its_native_cause_and_posts() {
    let (directory, main, _floor, empty, mut checkpoint) = fixture(None);
    prepare(&mut checkpoint, &main, empty).unwrap();
    checkpoint
        .publication
        .validate_once(&main, checkpoint.expected.as_ref().unwrap())
        .unwrap();
    std::fs::rename(
        directory.path().join(SIDECAR_NAME_V1),
        directory.path().join("missing-final"),
    )
    .unwrap();

    assert!(checkpoint.publication.exchange_once(&main).is_err());
    assert!(finish(&mut checkpoint, &main).is_err());
    let cause = checkpoint.publication.failure().unwrap() as *const dyn Error as *const ();
    assert!(checkpoint.publication.exchange_once(&main).is_err());

    assert_eq!(
        checkpoint.publication.failure().unwrap() as *const dyn Error as *const (),
        cause
    );
    assert!(matches!(
        checkpoint.publication.exchange,
        Some(Err(rustix::io::Errno::NOENT))
    ));
    assert!(matches!(
        checkpoint.publication.directory_sync,
        Some(Ok(()))
    ));
    assert!(
        checkpoint
            .publication
            .after
            .iter()
            .all(|name| name.open.is_some())
    );
    assert_eq!(
        std::fs::read(directory.path().join(STAGE)).unwrap(),
        checkpoint.expected.unwrap()
    );
    assert_eq!(
        std::fs::read(directory.path().join("missing-final")).unwrap(),
        b""
    );
}
