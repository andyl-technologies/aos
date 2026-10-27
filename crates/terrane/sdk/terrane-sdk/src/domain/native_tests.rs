//! Verifies domain namespace isolation through native filesystem bindings.

#![allow(
    clippy::unwrap_used,
    reason = "test setup and assertions fail by panicking"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::{DomainNamespace, DomainNamespaces};
use crate::store::{LocalFs, TokioLocalFs};

async fn directory() -> PathBuf {
    let random = TokioLocalFs.random_bytes(16).await.unwrap();
    let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = std::env::temp_dir().join(format!("terrane-domain-{name}"));
    tokio::fs::create_dir(&directory).await.unwrap();
    directory
}

#[tokio::test]
async fn dom_dedup_scope_rejects_symlink_before_creating_namespace_children() {
    let directory = directory().await;
    let outside = directory.join("outside");
    tokio::fs::create_dir(&outside).await.unwrap();
    let alias = directory.join("alias");
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    let namespaces = DomainNamespaces::new(vec![DomainNamespace {
        domain: "private:a".into(),
        root: alias.join("must-not-be-created"),
    }])
    .unwrap();

    assert!(namespaces.prepare_paths(&TokioLocalFs).await.is_err());
    assert!(!outside.join("must-not-be-created").exists());

    tokio::fs::remove_file(&alias).await.unwrap();
    tokio::fs::remove_dir(&outside).await.unwrap();
    tokio::fs::remove_dir(&directory).await.unwrap();
}

#[tokio::test]
async fn dom_dedup_scope_preserves_backend_authority_over_final_leaf_creation() {
    let directory = directory().await;
    let first = directory.join("first");
    let second = directory.join("second");
    let namespaces = DomainNamespaces::new(vec![
        DomainNamespace {
            domain: "private:a".into(),
            root: first.join("bucket"),
        },
        DomainNamespace {
            domain: "private:b".into(),
            root: second.join("bucket"),
        },
    ])
    .unwrap();

    namespaces.prepare_paths(&TokioLocalFs).await.unwrap();
    assert!(first.is_dir());
    assert!(second.is_dir());
    assert!(!first.join("bucket").exists());
    assert!(!second.join("bucket").exists());
    assert!(namespaces.verify_paths(&TokioLocalFs).await.is_err());

    // The backend owns final-leaf creation; this fixture exercises the binding
    // without pretending to establish or initialize a bucket ref inventory.
    for parent in [&first, &second] {
        TokioLocalFs
            .create_dir_new(&parent.join("bucket"))
            .await
            .unwrap();
    }
    namespaces.verify_paths(&TokioLocalFs).await.unwrap();
    assert_eq!(
        tokio::fs::metadata(first.join("bucket"))
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    assert_eq!(
        tokio::fs::metadata(second.join("bucket"))
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );

    tokio::fs::remove_dir(first.join("bucket")).await.unwrap();
    tokio::fs::remove_dir(&first).await.unwrap();
    tokio::fs::remove_dir(second.join("bucket")).await.unwrap();
    tokio::fs::remove_dir(&second).await.unwrap();
    tokio::fs::remove_dir(&directory).await.unwrap();
}

#[tokio::test]
async fn dom_dedup_scope_rejects_existing_private_root_with_other_user_access() {
    let directory = directory().await;
    let root = directory.join("insecure");
    tokio::fs::create_dir(&root).await.unwrap();
    tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
        .await
        .unwrap();
    let namespaces = DomainNamespaces::new(vec![DomainNamespace {
        domain: "private:a".into(),
        root: root.clone(),
    }])
    .unwrap();

    assert!(namespaces.prepare_paths(&TokioLocalFs).await.is_err());
    assert_eq!(
        tokio::fs::metadata(&root)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(
        tokio::fs::read_dir(&root)
            .await
            .unwrap()
            .next_entry()
            .await
            .unwrap()
            .is_none()
    );

    tokio::fs::remove_dir(&root).await.unwrap();
    tokio::fs::remove_dir(&directory).await.unwrap();
}
