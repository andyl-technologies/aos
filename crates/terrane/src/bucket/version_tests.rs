//! Exercises suffix-safe v2 locations and effect-free explicit legacy reads.

#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

use super::content_tests::{chunk_identity, raw, upload};
use super::tests::{Selected, Validator, config, fixture, log};
use super::*;
use crate::store::{
    ByteRange, ChunkPosition, ContentStore, IdentityPrefix, RefCasOutcome, RefLogAppendOutcome,
    RefStore, RefWatch, TokioClock, TokioLocalFs,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use terrane_core::bucket::{BucketCapabilities, PackExclusion};
use terrane_core::identity::{Identity, IdentityKind};
use terrane_core::refs::{RefClass, RefLogReason, RefLogRecord, RefName, RefRecord};

#[derive(Clone, Default)]
struct ReadOnlyFs {
    effects: Arc<AtomicUsize>,
    capability_reads: Arc<AtomicUsize>,
    empty_capability_read: Option<usize>,
}

impl ReadOnlyFs {
    fn denied<T>(&self) -> std::io::Result<T> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("legacy read attempted an effect"))
    }
}

#[async_trait::async_trait]
impl LocalFs for ReadOnlyFs {
    type Lock = crate::store::TokioFileLock;

    async fn random_bytes(&self, _length: usize) -> std::io::Result<Vec<u8>> {
        self.denied()
    }

    async fn lock_exclusive(&self, _path: &Path) -> std::io::Result<Self::Lock> {
        self.denied()
    }

    async fn write_new(&self, _path: &Path, _bytes: &[u8]) -> std::io::Result<()> {
        self.denied()
    }

    async fn create_dir_new(&self, _path: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn remove_file(&self, _path: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn rename(&self, _from: &Path, _to: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn rename_no_replace(&self, _from: &Path, _to: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn sync_file(&self, _path: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn sync_directory(&self, _path: &Path) -> std::io::Result<()> {
        self.denied()
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let bytes = TokioLocalFs.read(path).await?;
        if path.file_name().is_some_and(|name| name == "CAPABILITIES") {
            let read = self.capability_reads.fetch_add(1, Ordering::SeqCst) + 1;
            if self.empty_capability_read == Some(read) {
                return Ok(Vec::new());
            }
        }
        Ok(bytes)
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

async fn legacy_fixture() -> (
    super::tests::Bucket,
    Identity,
    RefRecord,
    RefLogRecord,
    Vec<u8>,
) {
    let bucket = fixture().await;
    let bytes = b"legacy bytes";
    let identity = chunk_identity(bytes);
    let encoded = raw(bytes);
    let profile = ChunkProfile::cdc_1m([0; 32]);
    bucket
        .put(upload(
            &encoded,
            &identity,
            bytes.len(),
            &profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let name = "refs/heads/_/legacy";
    let record = RefRecord::first([7; 32], 1, Locality::default());
    let legacy_log = RefLogRecord {
        record: record.clone(),
        previous_commit: None,
        expected_previous: None,
        principal: "legacy-writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 1,
    };
    let ref_path = bucket.root().join(name);
    TokioLocalFs
        .create_dir_all(ref_path.parent().unwrap())
        .await
        .unwrap();
    TokioLocalFs
        .write_new(&ref_path, &record.encode().unwrap())
        .await
        .unwrap();
    let log_key = BucketKey::legacy_reflog(name, 1).unwrap();
    let log_path = bucket.root().join(log_key.as_str());
    TokioLocalFs
        .create_dir_all(log_path.parent().unwrap())
        .await
        .unwrap();
    TokioLocalFs
        .write_new(&log_path, &legacy_log.encode().unwrap())
        .await
        .unwrap();
    let cap_path = bucket.root().join("CAPABILITIES");
    let mut capabilities =
        BucketCapabilities::decode(&TokioLocalFs.read(&cap_path).await.unwrap()).unwrap();
    capabilities.layout_version = 1;
    capabilities.ref_names = None;
    let original = capabilities.encode().unwrap();
    tokio::fs::write(cap_path, &original).await.unwrap();
    (bucket, identity, record, legacy_log, original)
}

#[tokio::test]
async fn v1_readonly_preserves_unknown_inventory_and_refuses_every_effect() {
    let (fixture, identity, first, first_log, original) = legacy_fixture().await;
    let fs = ReadOnlyFs::default();
    assert!(matches!(
        FileBucket::open(
            config(fixture.root().to_owned()),
            fs.clone(),
            TokioClock,
            Validator
        )
        .await
        .err()
        .unwrap()
        .kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(fs.effects.load(Ordering::SeqCst), 0);
    let legacy = FileBucket::open_legacy_read_only(
        config(fixture.root().to_owned()),
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(legacy.capabilities().refs, RefCapability::None);
    assert!(!legacy.capabilities().sealed);
    assert_eq!(
        legacy.get(&identity, None).await.unwrap(),
        raw(b"legacy bytes")
    );
    assert_eq!(
        legacy.has(std::slice::from_ref(&identity)).await.unwrap(),
        vec![true]
    );
    assert_eq!(
        legacy
            .list(&IdentityPrefix {
                kind: IdentityKind::Chunk,
                digest_prefix: Vec::new()
            })
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        legacy
            .published_identities(IdentityKind::Chunk)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        legacy
            .live_identities(IdentityKind::Chunk)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        legacy.ref_get("refs/heads/_/legacy").await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        legacy.ref_log_read("refs/heads/_/legacy", 1).await.unwrap(),
        vec![first_log.clone()]
    );
    let mut watch = legacy.ref_watch("refs/heads/_/legacy", 1).await.unwrap();
    assert_eq!(watch.next().await.unwrap(), Some(first_log));
    assert!(matches!(
        legacy.ref_names().await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    let second = first.advance([8; 32], 2).unwrap().selected();
    assert!(matches!(
        legacy
            .ref_cas("refs/heads/_/legacy", Some(&first), &second)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    assert!(matches!(
        legacy
            .ref_log_append("refs/heads/_/legacy", 2, &log(second, Some(first)))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    let encoded = raw(b"other");
    let offered = chunk_identity(b"other");
    let profile = ChunkProfile::cdc_1m([0; 32]);
    assert!(matches!(
        legacy
            .put(upload(
                &encoded,
                &offered,
                5,
                &profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    assert!(matches!(
        legacy.exclude(&identity).await.unwrap_err().kind(),
        StoreErrorKind::ReadOnly
    ));
    let exclusion = PackExclusion {
        pack_id: [0; 16],
        cycle: 1,
        epoch: 1,
    };
    assert!(matches!(
        legacy
            .restore_pack_locked(legacy.catalog().await.unwrap(), &exclusion)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    assert!(matches!(
        legacy
            .retire_pack_locked(
                legacy.catalog().await.unwrap(),
                exclusion,
                [0; 32],
                &Default::default()
            )
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    assert_eq!(fs.effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs
            .read(&fixture.root().join("CAPABILITIES"))
            .await
            .unwrap(),
        original
    );
    tokio::fs::remove_dir_all(fixture.root()).await.unwrap();
}

#[tokio::test]
async fn v1_readonly_rejects_layout_transition_without_upgrading_or_writing() {
    let (fixture, identity, _, _, original) = legacy_fixture().await;
    let fs = ReadOnlyFs::default();
    let legacy = FileBucket::open_legacy_read_only(
        config(fixture.root().to_owned()),
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let mut capabilities = BucketCapabilities::decode(&original).unwrap();
    capabilities.layout_version = 2;
    let transitioned = capabilities.encode().unwrap();
    tokio::fs::write(fixture.root().join("CAPABILITIES"), &transitioned)
        .await
        .unwrap();
    assert!(matches!(
        legacy.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        legacy
            .ref_get("refs/heads/_/legacy")
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        legacy
            .ref_log_read("refs/heads/_/legacy", 1)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(fs.effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs
            .read(&fixture.root().join("CAPABILITIES"))
            .await
            .unwrap(),
        transitioned
    );
    tokio::fs::remove_dir_all(fixture.root()).await.unwrap();
}

#[tokio::test]
async fn v2_effects_refuse_changed_version_under_the_actual_root_exclusion() {
    let bucket = fixture().await;
    let cap_path = bucket.root().join("CAPABILITIES");
    let mut capabilities =
        BucketCapabilities::decode(&TokioLocalFs.read(&cap_path).await.unwrap()).unwrap();
    assert_eq!(capabilities.layout_version, 2);
    capabilities.layout_version = 1;
    let changed = capabilities.encode().unwrap();
    tokio::fs::write(&cap_path, &changed).await.unwrap();
    let record = RefRecord::first([1; 32], 1, Locality::default()).selected();
    assert!(matches!(
        bucket
            .ref_log_append("refs/heads/_/main", 1, &log(record.clone(), None))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .ref_cas("refs/heads/_/main", None, &record)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    let encoded = raw(b"other");
    let offered = chunk_identity(b"other");
    let profile = ChunkProfile::cdc_1m([0; 32]);
    assert!(matches!(
        bucket
            .put(upload(
                &encoded,
                &offered,
                5,
                &profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket.exclude(&offered).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(TokioLocalFs.read(&cap_path).await.unwrap(), changed);
    assert!(
        !bucket
            .root()
            .join(BucketKey::ref_record("refs/heads/_/main").unwrap().as_str())
            .exists()
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn v2_migrated_numbered_log_coexists_with_a_numeric_descendant_ref() {
    let bucket = fixture().await;
    let parent = "refs/heads/_/a";
    let descendant = "refs/heads/_/a/00000000000000000001";
    let first = RefRecord::first([7; 32], 1, Locality::default());
    let legacy_log = RefLogRecord {
        record: first.clone(),
        previous_commit: None,
        expected_previous: None,
        principal: "legacy-writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 1,
    };
    let parent_key = BucketKey::ref_record(parent).unwrap();
    let log_key = BucketKey::reflog(parent, 1).unwrap();
    for (key, bytes) in [
        (&parent_key, first.encode().unwrap()),
        (&log_key, legacy_log.encode().unwrap()),
    ] {
        let path = bucket.root().join(key.as_str());
        TokioLocalFs
            .create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        TokioLocalFs.write_new(&path, &bytes).await.unwrap();
    }
    let cap_path = bucket.root().join("CAPABILITIES");
    let mut capabilities =
        BucketCapabilities::decode(&TokioLocalFs.read(&cap_path).await.unwrap()).unwrap();
    capabilities.ref_names = Some(vec![parent.into()]);
    tokio::fs::write(cap_path, capabilities.encode().unwrap())
        .await
        .unwrap();

    let child = RefRecord::first([8; 32], 1, Locality::default()).selected();
    bucket
        .ref_log_append(descendant, 1, &log(child.clone(), None))
        .await
        .unwrap();
    assert_eq!(
        bucket.ref_cas(descendant, None, &child).await.unwrap(),
        RefCasOutcome::Applied
    );
    let next = first.advance([9; 32], 2).unwrap().selected();
    bucket
        .ref_log_append(parent, 2, &log(next.clone(), Some(first)))
        .await
        .unwrap();
    assert_eq!(
        bucket
            .ref_cas(parent, Some(&legacy_log.record), &next)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    );

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.ref_get(parent).await.unwrap(), Some(next));
    assert_eq!(reopened.ref_get(descendant).await.unwrap(), Some(child));
    assert_eq!(reopened.ref_log_read(parent, 1).await.unwrap().len(), 2);
    assert_eq!(reopened.ref_log_read(descendant, 1).await.unwrap().len(), 1);
    assert!(bucket.root().join(log_key.as_str()).is_file());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn v2_registered_ref_classes_preserve_public_names_and_reopen() {
    let bucket = fixture().await;
    for (index, name) in [
        "refs/heads/_/a",
        "refs/heads/_/a/b",
        "refs/tags/_/a",
        "refs/tags/_/a/b",
        "refs/notes/profiles/_/a",
        "refs/notes/profiles/_/a/b",
        "refs/jobs/_/a",
        "refs/jobs/_/a/b",
        "refs/conflicts/_/a/00000000000000000001",
        "refs/conflicts/_/a/00000000000000000001/00000000000000000002",
        "refs/derived/_/a",
        "refs/derived/_/a/b",
    ]
    .into_iter()
    .enumerate()
    {
        let class = RefName::parse(name).unwrap().class();
        let mut first = RefRecord::first([index as u8; 32], 1, Locality::default());
        if matches!(
            class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            first = first.selected();
            bucket
                .ref_log_append(name, 1, &log(first.clone(), None))
                .await
                .unwrap();
        }
        assert_eq!(
            bucket.ref_cas(name, None, &first).await.unwrap(),
            RefCasOutcome::Applied
        );
        assert!(
            bucket
                .root()
                .join(BucketKey::ref_record(name).unwrap().as_str())
                .is_file()
        );
        let reopened = FileBucket::open(
            config(bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        assert_eq!(reopened.ref_get(name).await.unwrap(), Some(first.clone()));
        if matches!(
            class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            let next = first.advance([99; 32], 2).unwrap().selected();
            reopened
                .ref_log_append(name, 2, &log(next.clone(), Some(first.clone())))
                .await
                .unwrap();
            assert_eq!(
                reopened.ref_cas(name, Some(&first), &next).await.unwrap(),
                RefCasOutcome::Applied
            );
            assert_eq!(reopened.ref_log_read(name, 1).await.unwrap().len(), 2);
        }
    }
    let names = bucket.ref_names().await.unwrap();
    assert!(names.iter().all(|name| !name.ends_with(":record")));
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn v2_numbered_logs_require_migration_and_preserve_exact_existing_bytes() {
    let bucket = fixture().await;
    let name = "refs/heads/_/legacy";
    let record = RefRecord::first([7; 32], 1, Locality::default());
    let legacy_log = RefLogRecord {
        record,
        previous_commit: None,
        expected_previous: None,
        principal: "legacy-writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 1,
    };
    let cap_path = bucket.root().join("CAPABILITIES");
    let original_capabilities = TokioLocalFs.read(&cap_path).await.unwrap();
    let key = BucketKey::reflog(name, 1).unwrap();
    let path = bucket.root().join(key.as_str());

    assert!(matches!(
        bucket
            .ref_log_append(name, 1, &legacy_log)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(!path.exists());
    assert_eq!(bucket.ref_get(name).await.unwrap(), None);
    assert_eq!(
        TokioLocalFs.read(&cap_path).await.unwrap(),
        original_capabilities
    );

    // Author a migrated artifact as fixture setup; the backend offers no migrator.
    TokioLocalFs
        .create_dir_all(path.parent().unwrap())
        .await
        .unwrap();
    let original_log = legacy_log.encode().unwrap();
    TokioLocalFs.write_new(&path, &original_log).await.unwrap();
    assert_eq!(
        bucket.ref_log_append(name, 1, &legacy_log).await.unwrap(),
        RefLogAppendOutcome::Exists
    );
    let mut conflicting = legacy_log;
    conflicting.timestamp += 1;
    assert!(matches!(
        bucket
            .ref_log_append(name, 1, &conflicting)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(TokioLocalFs.read(&path).await.unwrap(), original_log);
    assert_eq!(
        TokioLocalFs.read(&cap_path).await.unwrap(),
        original_capabilities
    );
    assert!(bucket.ref_log_read(name, 1).await.unwrap().is_empty());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn v1_readonly_refuses_an_empty_backend_response_after_initial_validation() {
    let (fixture, _, _, _, original) = legacy_fixture().await;
    let fs = ReadOnlyFs {
        empty_capability_read: Some(2),
        ..ReadOnlyFs::default()
    };
    let error = FileBucket::open_legacy_read_only(
        config(fixture.root().to_owned()),
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert_eq!(fs.effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs
            .read(&fixture.root().join("CAPABILITIES"))
            .await
            .unwrap(),
        original
    );
    tokio::fs::remove_dir_all(fixture.root()).await.unwrap();
}
