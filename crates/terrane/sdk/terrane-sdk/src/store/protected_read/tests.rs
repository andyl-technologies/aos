//! Checks actual native protected records and ordered policy refusal.

#![allow(
    clippy::unwrap_used,
    reason = "fixture failures and missing native observations are test assertions"
)]

use super::NativeProtectedRead;
use crate::store::{LocalFs, StoreErrorKind, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let path = std::env::temp_dir().join(format!(
        "terrane-native-protected-read-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn owner(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().uid()
}

#[test]
fn protected_recipe_preserves_every_ordered_duplicate_parent() {
    let control = std::path::Path::new("/protected/control");
    let recipe = NativeProtectedRead::for_record(control, "publication/commits/7", 42);

    assert_eq!(recipe.path, control.join("publication/commits/7"));
    assert_eq!(
        recipe.parents,
        vec![
            control.join("publication"),
            control.join("publication"),
            control.join("publication/commits"),
            control.join("publication/commits"),
        ]
    );
}

#[tokio::test]
async fn native_protected_read_returns_exact_body_and_same_leaf_identity() {
    let control = directory();
    let path = control.join("backend-registration.cbor");
    std::fs::write(&path, b"exact protected bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::symlink_metadata(&path).unwrap();

    let read = TokioLocalFs
        .read_protected_record(NativeProtectedRead::for_record(
            &control,
            "backend-registration.cbor",
            owner(&control),
        ))
        .await
        .unwrap()
        .unwrap();
    let (bytes, metadata) = read.into_parts();

    assert_eq!(bytes.as_deref(), Some(b"exact protected bytes".as_slice()));
    let after = metadata.unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(std::fs::read(&path).unwrap(), b"exact protected bytes");
    std::fs::remove_dir_all(control).unwrap();
}

#[tokio::test]
async fn native_protected_read_preserves_missing_parent_and_leaf_absence() {
    let control = directory();

    for key in ["publication/commits/7", "backend-registration.cbor"] {
        let read = TokioLocalFs
            .read_protected_record(NativeProtectedRead::for_record(
                &control,
                key,
                owner(&control),
            ))
            .await
            .unwrap()
            .unwrap();
        let (bytes, metadata) = read.into_parts();

        assert!(bytes.is_none());
        assert!(metadata.is_none());
    }
    assert_eq!(std::fs::read_dir(&control).unwrap().count(), 0);
    std::fs::remove_dir_all(control).unwrap();
}

#[tokio::test]
async fn native_protected_read_unsafe_parent_precedes_later_missing_parent() {
    let control = directory();
    let publication = control.join("publication");
    std::fs::create_dir(&publication).unwrap();
    std::fs::set_permissions(&publication, std::fs::Permissions::from_mode(0o755)).unwrap();

    let result = TokioLocalFs
        .read_protected_record(NativeProtectedRead::for_record(
            &control,
            "publication/commits/7",
            owner(&control),
        ))
        .await;

    assert!(matches!(result, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported)));
    assert!(!publication.join("commits").exists());
    std::fs::remove_dir_all(control).unwrap();
}

#[tokio::test]
async fn native_protected_read_refuses_unsafe_leaf_without_returning_body() {
    let control = directory();
    let path = control.join("backend-registration.cbor");
    std::fs::write(&path, b"private bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let result = TokioLocalFs
        .read_protected_record(NativeProtectedRead::for_record(
            &control,
            "backend-registration.cbor",
            owner(&control),
        ))
        .await;

    assert!(matches!(result, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported)));
    assert_eq!(std::fs::read(&path).unwrap(), b"private bytes");
    std::fs::remove_dir_all(control).unwrap();
}

#[tokio::test]
async fn native_protected_read_refuses_hardlinked_and_symlinked_leaves() {
    let control = directory();
    let source = control.join("source");
    let path = control.join("backend-registration.cbor");
    std::fs::write(&source, b"private bytes").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::hard_link(&source, &path).unwrap();
    let hardlinked = TokioLocalFs
        .read_protected_record(NativeProtectedRead::for_record(
            &control,
            "backend-registration.cbor",
            owner(&control),
        ))
        .await;
    assert!(
        matches!(hardlinked, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported))
    );

    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&source, &path).unwrap();
    let symlinked = TokioLocalFs
        .read_protected_record(NativeProtectedRead::for_record(
            &control,
            "backend-registration.cbor",
            owner(&control),
        ))
        .await;
    assert!(matches!(symlinked, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported)));
    assert_eq!(std::fs::read(&source).unwrap(), b"private bytes");
    std::fs::remove_dir_all(control).unwrap();
}
