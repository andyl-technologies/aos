//! Requires real initial-host-root creator events on an explicitly supplied disk.
//!
//! These fixtures are source-only until scheduled in the native VM lane. They
//! never fabricate enrollment, namespace, guard, claim or setter authority.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Native fixture assertions intentionally panic."
)]

use super::*;
use crate::host_quota::DomainProvisioningGuard;
use std::{
    collections::BTreeSet,
    os::unix::fs::{FileExt, MetadataExt, PermissionsExt},
    sync::atomic::{AtomicU64, Ordering},
};
use terrane_format::{chunking::ChunkProfile, refs::Locality};
use terrane_sdk::{
    bucket::{FileBucketConfig, FileBucketPublicationConfig, enrollment::create_initial_bucket},
    store::{TokioClock, TokioLocalFs},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        inspection::host_root().expect("native fixture requires actual initial host root");
        let disk = std::env::var_os("TERRANE_INITIAL_ENROLLMENT_TEST_ROOT")
            .expect("native fixture requires explicitly supplied ordinary disk");
        let path = PathBuf::from(disk).join(format!(
            "initial-scaffold-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    async fn initial(&self) -> NativeInitialBucketEnrollment {
        create_initial_bucket(
            FileBucketConfig {
                root: self.0.join("bucket"),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: 0,
                    control: Some(self.0.join("control")),
                }),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: ChunkProfile::cdc_1m([0; 32]),
                locality: Locality::default(),
            },
            &TokioLocalFs,
            &TokioClock,
        )
        .await
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn actual_scaffold_creation_retains_all_original_inodes_bytes_and_exclusions() {
    let fixture = Fixture::new();
    let initial = fixture.initial().await;
    let root = File::open(initial.root()).unwrap();
    let original_root = root.metadata().unwrap();
    let original_paths: BTreeSet<_> = initial
        .directories()
        .map(|entry| entry.path().to_owned())
        .collect();
    let original_files: Vec<_> = initial
        .files()
        .map(|file| {
            (
                file.path().to_owned(),
                file.observed_metadata().ino(),
                file.expected_bytes().to_vec(),
            )
        })
        .collect();
    let guard = DomainProvisioningGuard::exclusive(&root).unwrap();

    let scaffold = NativeInitialHostScaffold::create(initial, guard).unwrap();
    scaffold.recheck().unwrap();

    assert_eq!(
        (
            root.metadata().unwrap().dev(),
            root.metadata().unwrap().ino()
        ),
        (original_root.dev(), original_root.ino())
    );
    for directory in scaffold.directories() {
        assert_eq!(
            directory.created(),
            !original_paths.contains(directory.path())
        );
    }
    assert!(scaffold.root().join("state/cache").is_dir());
    assert!(scaffold.root().join("state/publication").is_dir());
    for (path, inode, expected) in original_files {
        let observed = scaffold.files().find(|file| file.path() == path).unwrap();
        assert_eq!(observed.descriptor().metadata().unwrap().ino(), inode);
        let mut bytes = vec![0; expected.len()];
        observed.descriptor().read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, expected);
    }
    assert!(DomainProvisioningGuard::shared(&root).is_err());
    drop(scaffold);
    DomainProvisioningGuard::exclusive(&root).unwrap();
}

#[tokio::test]
async fn actual_initial_receipt_rejects_unknown_entries_before_scaffold_effects() {
    let fixture = Fixture::new();
    let initial = fixture.initial().await;
    let root = File::open(initial.root()).unwrap();
    std::fs::create_dir(initial.root().join("unrecognized")).unwrap();
    let path = initial.root().join("sealed");
    let guard = DomainProvisioningGuard::exclusive(&root).unwrap();

    assert!(NativeInitialHostScaffold::create(initial, guard).is_err());
    assert!(!path.exists());
}

#[tokio::test]
async fn actual_initial_receipt_refuses_shared_and_other_root_guards_before_effects() {
    for shared in [false, true] {
        let fixture = Fixture::new();
        let initial = fixture.initial().await;
        let root = File::open(initial.root()).unwrap();
        let path = initial.root().join("sealed");
        let guard = if shared {
            DomainProvisioningGuard::shared(&root).unwrap()
        } else {
            DomainProvisioningGuard::exclusive(&File::open(&fixture.0).unwrap()).unwrap()
        };

        assert!(NativeInitialHostScaffold::create(initial, guard).is_err());
        assert!(!path.exists());
    }
}

#[tokio::test]
async fn extended_scaffold_recheck_refuses_same_bytes_replacement_and_untracked_names() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let initial = fixture.initial().await;
        let guard =
            DomainProvisioningGuard::exclusive(&File::open(initial.root()).unwrap()).unwrap();
        let scaffold = NativeInitialHostScaffold::create(initial, guard).unwrap();
        if replace {
            let file = scaffold.files().next().unwrap();
            let replacement = fixture.0.join("replacement");
            std::fs::write(&replacement, file.expected_bytes()).unwrap();
            std::fs::rename(replacement, file.path()).unwrap();
        } else {
            std::fs::write(scaffold.root().join("state/cache/untracked"), b"untracked").unwrap();
        }

        assert!(scaffold.recheck().is_err());
    }
}

#[tokio::test]
async fn extended_observation_closes_on_original_preimages_after_actual_enumeration() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let initial = fixture.initial().await;
        let guard =
            DomainProvisioningGuard::exclusive(&File::open(initial.root()).unwrap()).unwrap();
        let scaffold = NativeInitialHostScaffold::create(initial, guard).unwrap();
        let observed = inspection::observe_namespace(&scaffold).unwrap();

        // Pause the actual production observation after enumeration. These
        // physical changes occur before its closing pass, without a hook,
        // synthetic receipt or normalization of the expected metadata.
        if replace {
            let file = scaffold.files().next().unwrap();
            let replacement = fixture.0.join("closing-replacement");
            std::fs::write(&replacement, file.expected_bytes()).unwrap();
            std::fs::rename(replacement, file.path()).unwrap();
        } else {
            std::fs::write(scaffold.root().join("state/cache/late-entry"), b"late").unwrap();
        }

        assert!(observed.close().is_err());
    }
}
