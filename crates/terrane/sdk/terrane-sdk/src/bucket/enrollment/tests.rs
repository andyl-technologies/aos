//! Exercises genuine creator-only enrollment and exact retained preimages.
//!
//! No fixture assigns projects, persists host claims or installs credentials.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture assertions intentionally panic."
)]

use super::super::{
    test_fs::{ProbeFs, Stop},
    tests::Fixture,
};
use super::*;
use crate::store::{TokioClock, TokioLocalFs};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use terrane_format::{bucket::BucketCapabilities, gc::publication::Activation};

#[tokio::test]
async fn fresh_enrollment_keeps_original_inodes_and_exclusion_through_final_genesis() {
    let fixture = Fixture::new();
    let pending = fixture.staged().await;
    let root = std::fs::symlink_metadata(&fixture.root).unwrap();
    let control = std::fs::symlink_metadata(&fixture.control).unwrap();
    let coordination = pending.exclusions[0].file.metadata().unwrap();
    let fs = ProbeFs::default();
    let receipt = activate(&fs, pending, fixture.request()).await.unwrap();
    receipt.verify_inline().unwrap();

    assert_eq!(receipt.root(), fixture.root);
    assert_eq!(receipt.control(), fixture.control);
    assert_eq!(receipt.operator_uid(), fixture.owner);
    let BackendBinding::Local {
        root_device,
        root_inode,
        coordination_device,
        coordination_inode,
        ..
    } = receipt.binding()
    else {
        panic!("not local");
    };
    assert_eq!((*root_device, *root_inode), (root.dev(), root.ino()));
    assert_eq!(
        (*coordination_device, *coordination_inode),
        (coordination.dev(), coordination.ino())
    );
    for (path, original) in [(&fixture.root, root), (&fixture.control, control)] {
        let actual = std::fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (
                actual.dev(),
                actual.ino(),
                actual.uid(),
                actual.gid(),
                actual.mode()
            ),
            (
                original.dev(),
                original.ino(),
                original.uid(),
                original.gid(),
                original.mode()
            )
        );
    }
    for file in receipt.files() {
        let mut actual = vec![0; file.expected_bytes().len()];
        file.descriptor().read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, file.expected_bytes());
        assert_eq!(file.descriptor().metadata().unwrap().nlink(), 1);
    }
    let cap = receipt
        .genesis()
        .changes
        .iter()
        .find(|row| row.key == "CAPABILITIES")
        .unwrap();
    let cap = BucketCapabilities::decode(cap.new.as_deref().unwrap()).unwrap();
    assert_eq!(cap.ref_names, Some(Vec::new()));
    assert!(receipt.genesis().new.branches.is_empty());
    let registration = receipt
        .files()
        .find(|file| file.path() == fixture.control.join("backend-registration.cbor"))
        .unwrap();
    assert_eq!(
        terrane_format::gc::publication::BackendRegistration::decode(registration.expected_bytes())
            .unwrap()
            .activation,
        Activation::Active
    );
    assert_eq!(fs.ordinary_effects(), 0);

    let lock_path = fixture.root.join(
        terrane_format::bucket::BucketKey::parse("CAPABILITIES")
            .unwrap()
            .lock_name(),
    );
    let contender = File::open(lock_path).unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(receipt);
    contender.try_lock().unwrap();
}

#[tokio::test]
async fn fresh_enrollment_public_factory_refuses_every_existing_root() {
    let fixture = Fixture::new();
    let receipt = crate::bucket::enrollment::create_initial_bucket(
        fixture.config(),
        &TokioLocalFs,
        &TokioClock,
    )
    .await
    .unwrap();
    assert!(
        crate::bucket::enrollment::create_initial_bucket(
            fixture.config(),
            &TokioLocalFs,
            &TokioClock
        )
        .await
        .is_err()
    );
    receipt.verify_inline().unwrap();
    drop(receipt);

    let fixture = Fixture::new();
    std::fs::create_dir(&fixture.root).unwrap();
    assert!(
        crate::bucket::enrollment::create_initial_bucket(
            fixture.config(),
            &TokioLocalFs,
            &TokioClock
        )
        .await
        .is_err()
    );
    assert!(!fixture.control.exists());
}

#[tokio::test]
async fn fresh_enrollment_refuses_unbranded_and_mismatched_native_receipts() {
    for case in ["unbranded", "wrong configuration"] {
        let fixture = Fixture::new();
        let mut receipt = fixture.staged().await;
        let mut expected = fixture.request();
        if case == "unbranded" {
            receipt.request.creator = None;
        } else {
            expected.timestamp += 1;
        }
        let result = activate(&TokioLocalFs, receipt, expected).await;
        assert!(
            matches!(result, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported)),
            "{case}"
        );
        assert!(!fixture.control.join("publication/commits/0").exists());
    }
}

#[tokio::test]
async fn fresh_enrollment_refuses_failed_activation_and_false_probe_success() {
    for case in ["slot failure", "wrong range", "false create probe"] {
        let fixture = Fixture::new();
        let pending = fixture.staged().await;
        let fs = ProbeFs::default();
        match case {
            "slot failure" => fs.stop(Stop::BeforeSlot),
            "wrong range" => fs.wrong_range(),
            _ => fs.noop_probe(),
        }
        assert!(
            activate(&fs, pending, fixture.request()).await.is_err(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn fresh_enrollment_rejects_extra_entries_before_receipt_sealing() {
    for case in ["regular", "directory", "symlink", "hardlink"] {
        let fixture = Fixture::new();
        let pending = fixture.staged().await;
        let path = fixture.root.join("unexpected");
        match case {
            "regular" => std::fs::write(path, b"foreign").unwrap(),
            "directory" => std::fs::create_dir(path).unwrap(),
            "symlink" => std::os::unix::fs::symlink(&fixture.control, path).unwrap(),
            _ => std::fs::hard_link(fixture.root.join("objects/index/1/0.idx"), path).unwrap(),
        }
        assert!(
            activate(&TokioLocalFs, pending, fixture.request())
                .await
                .is_err(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn fresh_enrollment_rechecks_bodies_incarnations_modes_and_complete_namespace() {
    for case in [
        "body",
        "equal replacement",
        "file mode",
        "directory mode",
        "extra payload",
        "extra control",
        "hardlink",
        "missing leaf",
        "root replacement",
        "control replacement",
    ] {
        let fixture = Fixture::new();
        let receipt = crate::bucket::enrollment::create_initial_bucket(
            fixture.config(),
            &TokioLocalFs,
            &TokioClock,
        )
        .await
        .unwrap();
        let path = fixture.root.join("objects/index/1/0.idx");
        match case {
            "body" => {
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[0] ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
            "equal replacement" => {
                let temporary = fixture.parent.join("replacement");
                std::fs::write(&temporary, std::fs::read(&path).unwrap()).unwrap();
                std::fs::rename(temporary, path).unwrap();
            }
            "file mode" => {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap()
            }
            "directory mode" => std::fs::set_permissions(
                fixture.root.join("objects"),
                std::fs::Permissions::from_mode(0o750),
            )
            .unwrap(),
            "extra payload" => std::fs::write(fixture.root.join("foreign"), b"extra").unwrap(),
            "extra control" => std::fs::write(fixture.control.join("foreign"), b"extra").unwrap(),
            "hardlink" => std::fs::hard_link(path, fixture.parent.join("external-alias")).unwrap(),
            "missing leaf" => std::fs::remove_file(path).unwrap(),
            "root replacement" => {
                std::fs::rename(&fixture.root, fixture.parent.join("original-root")).unwrap();
                std::fs::create_dir(&fixture.root).unwrap();
                std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            _ => {
                std::fs::rename(&fixture.control, fixture.parent.join("original-control")).unwrap();
                std::fs::create_dir(&fixture.control).unwrap();
                std::fs::set_permissions(&fixture.control, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
        }
        assert!(receipt.verify_inline().is_err(), "{case}");
    }
}
