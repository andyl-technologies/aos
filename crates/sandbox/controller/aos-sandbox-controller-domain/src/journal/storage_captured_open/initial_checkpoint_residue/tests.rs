//! Exercises real pending names without manufacturing receiving or TPM authority.

use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::*;

fn fixture() -> (tempfile::TempDir, Journal) {
    let executable = std::env::current_exe().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("initial-checkpoint-residue-")
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
    let (main, _) = opening.take_captured_opened().unwrap();
    (directory, main)
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn method46_initial_checkpoint_residue_accepts_only_stable_absence_or_safe_empty_file() {
    for present in [false, true] {
        let (directory, main) = fixture();
        let path = directory.path().join(INITIAL_PENDING_NAME_V1);
        if present {
            write(&path, b"");
        }
        let mut residue = InitialCheckpointResidueOriginalV1::new();

        residue.capture_once(&main);

        assert!(matches!(residue.result, Some(Ok(()))));
        assert!(residue.failure().is_none());
        assert_eq!(path.exists(), present);
        for sample in &residue.samples {
            if present {
                assert!(matches!(sample.open, Some(Ok(_))));
                assert!(
                    sample
                        .metadata
                        .iter()
                        .all(|result| matches!(result, Some(Ok(_))))
                );
            } else {
                assert!(sample.missing());
            }
        }
    }
}

#[test]
fn method46_initial_checkpoint_residue_rejects_unsafe_and_nonempty_names_without_repair() {
    for variant in 0..6 {
        let (directory, main) = fixture();
        let pending = directory.path().join(INITIAL_PENDING_NAME_V1);
        let other = directory.path().join("preserved-other");
        match variant {
            0 => write(&pending, b"unfinished checkpoint"),
            1 => write(&pending, &[7; 429]),
            2 => {
                write(&other, b"foreign target");
                symlink(&other, &pending).unwrap();
            }
            3 => std::fs::create_dir(&pending).unwrap(),
            4 => {
                write(&pending, b"");
                std::fs::hard_link(&pending, &other).unwrap();
            }
            5 => {
                write(&pending, b"");
                std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
            _ => unreachable!(),
        }
        let before = std::fs::symlink_metadata(&pending).unwrap();
        let mut residue = InitialCheckpointResidueOriginalV1::new();

        residue.capture_once(&main);

        assert!(matches!(residue.result, Some(Err(_))), "variant {variant}");
        assert!(residue.failure().is_some());
        assert!(residue.samples.iter().all(|sample| sample.open.is_some()));
        let after = std::fs::symlink_metadata(&pending).unwrap();
        assert!(
            FileIdentity::from_metadata_data_v1(&before)
                == FileIdentity::from_metadata_data_v1(&after),
            "variant {variant} changed the retained pending file"
        );
        assert_eq!(before.mode(), after.mode());
        assert_eq!(before.nlink(), after.nlink());
        if variant == 2 {
            assert_eq!(std::fs::read(other).unwrap(), b"foreign target");
        }
    }
}

#[test]
fn method46_initial_checkpoint_residue_fences_appearance_disappearance_replacement_and_mutation() {
    for variant in 0..5 {
        let (directory, main) = fixture();
        let pending = directory.path().join(INITIAL_PENDING_NAME_V1);
        let saved = directory.path().join("preserved-empty");
        if variant != 0 {
            write(&pending, b"");
        }
        let mut residue = InitialCheckpointResidueOriginalV1::new();
        residue.samples[0].capture(&main);

        match variant {
            0 => write(&pending, b""),
            1 => std::fs::rename(&pending, &saved).unwrap(),
            2 => {
                std::fs::rename(&pending, &saved).unwrap();
                write(&pending, b"");
            }
            3 => write(&pending, b"changed"),
            4 => std::fs::hard_link(&pending, &saved).unwrap(),
            _ => unreachable!(),
        }
        residue.samples[1].capture(&main);
        residue.finish(&main);

        assert!(matches!(residue.result, Some(Err(_))), "variant {variant}");
        assert!(residue.failure().is_some());
        if matches!(variant, 1 | 2 | 4) {
            assert_eq!(std::fs::read(saved).unwrap(), b"");
        }
    }
}

#[test]
fn method46_initial_checkpoint_residue_keeps_first_native_failure_and_independent_after() {
    let (directory, main) = fixture();
    let pending = directory.path().join(INITIAL_PENDING_NAME_V1);
    let saved = directory.path().join("preserved-symlink");
    symlink("missing-target", &pending).unwrap();
    let mut residue = InitialCheckpointResidueOriginalV1::new();
    residue.samples[0].capture(&main);
    let original = residue.samples[0].failure().unwrap() as *const dyn Error as *const ();

    std::fs::rename(&pending, &saved).unwrap();
    write(&pending, b"");
    residue.samples[1].capture(&main);
    residue.finish(&main);

    assert!(
        residue.samples[1]
            .require_empty(rustix::process::geteuid().as_raw())
            .is_ok()
    );
    assert_eq!(
        residue.failure().unwrap() as *const dyn Error as *const (),
        original
    );
    assert!(matches!(residue.result, Some(Err(_))));
    residue.capture_once(&main);
    assert_eq!(
        residue.failure().unwrap() as *const dyn Error as *const (),
        original
    );
    assert!(std::fs::symlink_metadata(saved).unwrap().is_symlink());
    assert_eq!(std::fs::read(pending).unwrap(), b"");
}
