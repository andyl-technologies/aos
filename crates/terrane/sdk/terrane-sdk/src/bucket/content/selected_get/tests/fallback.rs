//! Delegates real I/O while explicitly declining optional native retention.

use super::*;
use crate::bucket::tests::Validator;
use crate::store::{
    NativeEffectFailure, NativeExclusion, NativeFsEffect, NativePublicationInitialization,
    NativePublicationInitializationOutcome, TokioClock, TokioFileLock,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use terrane_format::bucket::BucketCapabilities;

#[derive(Clone)]
struct OptionalRetention {
    supported: Arc<AtomicBool>,
    mutations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl LocalFs for OptionalRetention {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        if self.supported.load(Ordering::SeqCst) {
            TokioLocalFs.retain_native_exclusion(held)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "fixture binding declines optional native retention",
            ))
        }
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
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

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_directory(path).await
    }
}

/// Exercises copied, unsupported-retention and explicit legacy content reads.
///
/// # Errors
/// Preserves native I/O, path, capability encoding, initialization and read failures.
///
/// # Panics
/// Panics if fixture initialization fails or bytes, physical identities, effect
/// counts or control absence differ from the required behavior.
pub(super) async fn check() -> TestResult {
    let fixture = Fixture::new().await?;
    check_quiescent_copy(&fixture).await?;
    let fs = OptionalRetention {
        supported: Arc::new(AtomicBool::new(true)),
        mutations: Arc::default(),
    };
    // This binding has not opted into body batches. It must perform no I/O,
    // even for an absent path, and preserve its original scalar fault boundary.
    assert!(
        crate::store::native_publication_effects::PayloadRangeCapture::read_ordinary_bodies(
            &fs,
            fixture.bucket.root(),
            &[PathBuf::from("objects/index/0/MANIFEST")],
        )
        .await?
        .is_none()
    );
    assert_eq!(fs.mutations.load(Ordering::SeqCst), 0);

    let configuration = fixture.bucket.inner.config.clone();
    let ordinary =
        FileBucket::open(configuration.clone(), fs.clone(), TokioClock, Validator).await?;
    fs.supported.store(false, Ordering::SeqCst);
    let before = fs.mutations.load(Ordering::SeqCst);
    assert_eq!(
        ordinary.get(&fixture.identity, None).await?,
        fixture.encoded
    );
    let range = ByteRange {
        start: 1,
        length: 5,
    };
    assert_eq!(
        ordinary.get(&fixture.identity, Some(range)).await?,
        fixture.encoded[1..6]
    );
    assert_eq!(fs.mutations.load(Ordering::SeqCst), before);

    // Produce the explicit legacy fixture from real durable payload files.
    // The legacy reader creates no replacement control or coordination state.
    let path = fixture.bucket.root().join("CAPABILITIES");
    let mut capabilities = BucketCapabilities::decode(&TokioLocalFs.read_nofollow(&path).await?)?;
    capabilities.layout_version = 1;
    capabilities.publication_protocol = None;
    capabilities.ref_names = None;
    tokio::fs::write(&path, capabilities.encode()?).await?;
    tokio::fs::remove_dir_all(control_path(fixture.bucket.root())).await?;
    let legacy =
        FileBucket::open_legacy_read_only(configuration, fs.clone(), TokioClock, Validator).await?;
    assert_eq!(legacy.get(&fixture.identity, None).await?, fixture.encoded);
    assert_eq!(
        legacy.get(&fixture.identity, Some(range)).await?,
        fixture.encoded[1..6]
    );
    assert_eq!(fs.mutations.load(Ordering::SeqCst), before);
    assert!(!control_path(fixture.bucket.root()).exists());
    tokio::fs::remove_dir_all(fixture.bucket.root()).await?;
    Ok(())
}

/// Exercises readable copied bytes after genuine independent activation.
async fn check_quiescent_copy(fixture: &Fixture) -> TestResult {
    let nonce = TokioLocalFs.random_bytes(16).await?;
    let tag: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut config = fixture.bucket.inner.config.clone();
    config.root = fixture
        .bucket
        .root()
        .with_extension(format!("ordinary-copy-{tag}"));
    config
        .publication_control
        .as_mut()
        .ok_or("missing actual operator configuration")?
        .control = None;

    let holder = fixture.bucket.read_exclusion().await?;
    let mut pending = vec![(fixture.bucket.root().to_owned(), config.root.clone())];
    while let Some((source, target)) = pending.pop() {
        tokio::fs::create_dir_all(&target).await?;
        let mut entries = tokio::fs::read_dir(source).await?;
        while let Some(entry) = entries.next_entry().await? {
            let output = target.join(entry.file_name());
            if entry.file_type().await?.is_dir() {
                pending.push((entry.path(), output));
            } else {
                tokio::fs::copy(entry.path(), output).await?;
            }
        }
    }
    drop(holder);

    let copied =
        FileBucket::initialize_portable_copy(config, TokioLocalFs, TokioClock, Validator).await?;
    let relative = fixture.pack.strip_prefix(fixture.bucket.root())?;
    let original = tokio::fs::symlink_metadata(&fixture.pack).await?;
    let current = tokio::fs::symlink_metadata(copied.root().join(relative)).await?;
    assert_ne!(
        (original.dev(), original.ino()),
        (current.dev(), current.ino())
    );
    assert_eq!(copied.get(&fixture.identity, None).await?, fixture.encoded);
    assert_eq!(
        copied
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 5
                })
            )
            .await?,
        fixture.encoded[1..6],
    );
    tokio::fs::remove_dir_all(control_path(copied.root())).await?;
    tokio::fs::remove_dir_all(copied.root()).await?;
    Ok(())
}
