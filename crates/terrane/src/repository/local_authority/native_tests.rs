//! Exercises native retention refusal before effects on an actual legacy bucket.

#![allow(
    clippy::unwrap_used,
    reason = "actual fixtures and assertions fail the test directly"
)]

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::*;
use crate::{
    bucket::FileBucketConfig,
    guard::GuardConfig,
    ref_advance::CommitTiming,
    repository::MetadataValidator,
    store::{ByteRange, TokioClock, TokioLocalFs},
};
use terrane_core::{
    bucket::{BucketCapabilities, StoreProfile},
    chunking::ChunkProfile,
    refs::Locality,
};

#[derive(Clone, Default)]
struct ReadOnlyFs {
    effects: Arc<AtomicUsize>,
}

impl ReadOnlyFs {
    fn denied<T>(&self) -> std::io::Result<T> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other(
            "read-only fixture attempted an effect",
        ))
    }
}

#[async_trait::async_trait]
impl LocalFs for ReadOnlyFs {
    type Lock = crate::store::TokioFileLock;

    async fn random_bytes(&self, _: usize) -> std::io::Result<Vec<u8>> {
        self.denied()
    }

    async fn lock_exclusive(&self, _: &Path) -> std::io::Result<Self::Lock> {
        self.denied()
    }

    async fn write_new(&self, _: &Path, _: &[u8]) -> std::io::Result<()> {
        self.denied()
    }

    async fn create_dir_new(&self, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn create_dir_all(&self, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn remove_file(&self, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn rename(&self, _: &Path, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn rename_no_replace(&self, _: &Path, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn sync_file(&self, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn sync_directory(&self, _: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn set_permissions_and_sync(
        &self,
        _: &Path,
        _: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.denied()
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }
}

#[tokio::test]
async fn native_retention_refuses_legacy_before_any_control_or_lock_effect() {
    use std::os::unix::fs::MetadataExt;

    let fs = TokioLocalFs;
    let entropy = fs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-native-readonly-{suffix}"));
    fs.create_dir_new(&parent).await.unwrap();
    let root = parent.join("bucket");
    let control = parent.join("authority");
    let owner = fs.metadata(&parent).await.unwrap().uid();
    let profile = ChunkProfile::cdc_1m([42; 32]);
    let config = FileBucketConfig {
        publication_control: None,
        root: root.clone(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: profile.clone(),
        locality: Locality::default(),
    };
    // A selected bucket cannot become legacy by rewriting its mutable cache.
    // Create only the genuine legacy payload consumed by the read-only factory.
    fs.create_dir_new(&root).await.unwrap();
    let cap_path = root.join("CAPABILITIES");
    let capabilities = BucketCapabilities {
        layout_version: 1,
        create_if_absent: true,
        compare_and_swap: true,
        ranges: true,
        presign: false,
        multi_writer: false,
        probed_at: 0,
        profile: StoreProfile {
            identity: "terrane-v1".into(),
            algorithm: "blake3".into(),
            chunk: "cdc-1m".into(),
            seed: profile.seed(),
        },
        generation: None,
        ref_names: None,
        publication_protocol: None,
    };
    let original = capabilities.encode().unwrap();
    fs.write_new(&cap_path, &original).await.unwrap();
    fs.sync_file(&cap_path).await.unwrap();
    fs.sync_directory(&root).await.unwrap();

    let readonly = ReadOnlyFs::default();
    let bucket = FileBucket::open_legacy_read_only(
        config,
        readonly.clone(),
        TokioClock,
        MetadataValidator::new(profile.clone()),
    )
    .await
    .unwrap();
    assert_eq!(bucket.capabilities().refs, RefCapability::None);
    let guard = Guard::new(
        bucket,
        TokioClock,
        Vec::new(),
        GuardConfig {
            store_name: "local".into(),
            private_domain: "private:owner".into(),
            home: Locality::default(),
            initial_acl: vec![("owner".into(), 31)],
            min_chunk_size: profile.minimum() as u64,
            storage_domain: "private:owner".into(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: Box::new(profile),
            policy_authority: None,
        },
    );
    let timing = CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )
    .unwrap();
    let coordinator = Coordinator::new(guard, timing, readonly.clone());
    let namespace = DomainNamespace {
        root: root.clone(),
        domain: "private:owner".into(),
    };

    let result =
        Repository::initialize_native_retention(coordinator, &namespace, &control, owner).await;

    assert!(
        matches!(result, Err(Error::Store(error)) if error.kind() == &StoreErrorKind::ReadOnly)
    );
    assert_eq!(readonly.effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs.symlink_metadata(&control).await.unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(fs.read_nofollow(&cap_path).await.unwrap(), original);

    let mut directories = vec![parent];
    let mut next = 0;
    while next < directories.len() {
        for path in fs.read_dir(&directories[next]).await.unwrap() {
            let metadata = fs.symlink_metadata(&path).await.unwrap();
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(path);
            } else {
                fs.remove_file(&path).await.unwrap();
            }
        }
        next += 1;
    }
    for directory in directories.into_iter().rev() {
        fs.remove_dir(&directory).await.unwrap();
    }
}
