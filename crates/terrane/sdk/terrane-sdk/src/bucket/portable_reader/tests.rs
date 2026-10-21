//! Exercises genuine portable publication, final shared modes and bounded refusal.
//!
//! These fixtures initialize actual T1 buckets. They install no role credentials
//! and make no native host-custody, quota or live-content-serving claim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test assertions panic on fixture failures."
)]

mod source;

use super::*;
use crate::{
    bucket::{FileBucketConfig, tests as bucket_tests},
    ref_advance::tests::{Validator, fixture, request_file, token},
    store::{StoreErrorKind, TokioClock},
};
use source::ReadSource;
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};
use terrane_format::{
    bucket::BucketCapabilities, chunking::ChunkProfile, gc::publication::CommittedSelection,
};

const NAME: &str = "refs/heads/tenant/main";

struct Cleanup(Vec<PathBuf>);

impl Cleanup {
    fn new(root: &Path) -> Self {
        let name = root.file_name().unwrap().to_string_lossy();
        Self(vec![
            root.to_owned(),
            bucket_tests::control_path(root),
            root.with_file_name(format!("{name}-operator")),
            root.with_file_name(format!("{name}-original-control")),
        ])
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            if let Err(error) = std::fs::remove_dir_all(path) {
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::NotFound,
                    "{}",
                    path.display()
                );
            }
        }
    }
}

async fn validate(
    config: FileBucketConfig,
    source: &ReadSource,
    limits: PortableReadLimits,
) -> Result<ValidatedPortableBucket, crate::store::StoreFailure> {
    validate_existing(config, source, TokioClock, Validator, limits).await
}

#[tokio::test]
async fn portable_reader_validates_shared_modes_without_original_control_or_effects() {
    let native = fixture().await;
    let root = native.store().root();
    let _cleanup = Cleanup::new(root);
    let mut session = native.begin(NAME, &token(), "sdk").await.unwrap();
    let head = native
        .advance(
            &mut session,
            request_file(Vec::new(), b"portable reader body"),
        )
        .await
        .unwrap();
    let config = native.store().inner.config.clone();
    let selected = native
        .store()
        .portable_copy_payload()
        .await
        .unwrap()
        .logical;

    // A selected checkpoint, not mutable caches or the Original owner, chooses
    // this read-only observation. Shared ancestor modes remain ordinary data.
    tokio::fs::set_permissions(
        root.join("objects"),
        std::fs::Permissions::from_mode(0o2770),
    )
    .await
    .unwrap();
    tokio::fs::write(root.join("CAPABILITIES"), b"stale physical cache")
        .await
        .unwrap();
    let source = ReadSource::new(root);
    let snapshot = validate(config, &source, PortableReadLimits::default())
        .await
        .unwrap();
    let cap_key = BucketKey::parse("CAPABILITIES").unwrap();
    let cap =
        BucketCapabilities::decode(snapshot.selected_value(&cap_key).unwrap().unwrap()).unwrap();

    assert_eq!(snapshot.root(), root);
    assert_eq!(snapshot.profile(), &cap.profile);
    assert_eq!(
        snapshot.capabilities().refs,
        crate::store::RefCapability::None
    );
    assert_eq!(
        snapshot.capabilities().ranges,
        crate::store::RangeCapability::WholeObjectOnly
    );
    assert_eq!(
        snapshot.selected_history().branches[0].selection,
        CommittedSelection::Selected(head.into())
    );
    assert_eq!(
        snapshot.selected_value(&cap_key).unwrap().unwrap(),
        selected["CAPABILITIES"].as_deref().unwrap()
    );
    assert_eq!(
        snapshot.selected_value(&BucketKey::parse("gc/lease").unwrap()),
        Some(None)
    );
    assert_eq!(
        tokio::fs::read(root.join("CAPABILITIES")).await.unwrap(),
        b"stale physical cache"
    );
    assert!(!source.mutations.load(Ordering::SeqCst));
    assert!(!source.ranges.lock().unwrap().is_empty());
    assert_eq!(
        snapshot.generation_manifest().generation,
        cap.generation.unwrap()
    );
}

#[tokio::test]
async fn portable_reader_rejects_missing_or_corrupt_selected_closure() {
    let native = fixture().await;
    let root = native.store().root();
    let _cleanup = Cleanup::new(root);
    let mut session = native.begin(NAME, &token(), "sdk").await.unwrap();
    let head = native
        .advance(
            &mut session,
            request_file(Vec::new(), b"checked full closure"),
        )
        .await
        .unwrap();
    let config = native.store().inner.config.clone();
    let baseline = validate(
        config.clone(),
        &ReadSource::new(root),
        PortableReadLimits::default(),
    )
    .await
    .unwrap();
    let manifest = baseline.generation_manifest();
    let inventory = &manifest.inventory.as_ref().unwrap()[0];
    let pack = crate::pack::PackId::from_random_bytes(inventory.pack_id);
    let log =
        BucketKey::reflog_candidate(NAME, head.seq, head.candidate_id.as_ref().unwrap()).unwrap();
    let paths = [
        "publication/PORTABLE".to_owned(),
        baseline.checkpoint().key.clone(),
        format!("objects/index/{}/MANIFEST", manifest.generation),
        format!(
            "objects/index/{}/{}.idx",
            manifest.generation, manifest.shards[0].shard
        ),
        pack.pack_key(),
        pack.index_key(),
        log.as_str().to_owned(),
    ];

    for key in paths {
        let path = root.join(&key);
        let before = tokio::fs::read(&path).await.unwrap();
        tokio::fs::write(&path, b"corrupt selected input")
            .await
            .unwrap();
        assert!(
            validate(
                config.clone(),
                &ReadSource::new(root),
                PortableReadLimits::default()
            )
            .await
            .is_err(),
            "{key}"
        );
        tokio::fs::write(&path, &before).await.unwrap();

        let hidden = path.with_extension("portable-reader-hidden");
        tokio::fs::rename(&path, &hidden).await.unwrap();
        assert!(
            validate(
                config.clone(),
                &ReadSource::new(root),
                PortableReadLimits::default()
            )
            .await
            .is_err(),
            "missing {key}"
        );
        tokio::fs::rename(hidden, path).await.unwrap();
    }
}

#[tokio::test]
async fn portable_reader_rejects_source_profile_mismatch_and_symlinked_inputs() {
    let bucket = bucket_tests::fixture().await;
    let root = bucket.root();
    let _cleanup = Cleanup::new(root);
    let mut config = bucket.inner.config.clone();
    config.chunk_profile = ChunkProfile::cdc_1m([1; 32]);
    assert!(
        validate(
            config,
            &ReadSource::new(root),
            PortableReadLimits::default()
        )
        .await
        .is_err()
    );

    let pointer = root.join("publication/PORTABLE");
    let hidden = root.join("publication/pointer-hidden");
    tokio::fs::rename(&pointer, &hidden).await.unwrap();
    std::os::unix::fs::symlink(&hidden, &pointer).unwrap();
    assert!(
        validate(
            bucket.inner.config.clone(),
            &ReadSource::new(root),
            PortableReadLimits::default()
        )
        .await
        .is_err()
    );
    tokio::fs::remove_file(&pointer).await.unwrap();
    tokio::fs::rename(&hidden, &pointer).await.unwrap();

    let objects = root.join("objects");
    let hidden = root.join("objects-hidden");
    tokio::fs::rename(&objects, &hidden).await.unwrap();
    std::os::unix::fs::symlink(&hidden, &objects).unwrap();
    assert!(
        validate(
            bucket.inner.config.clone(),
            &ReadSource::new(root),
            PortableReadLimits::default()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn portable_reader_enforces_file_aggregate_count_and_selected_budgets() {
    let bucket = bucket_tests::fixture().await;
    let root = bucket.root();
    let _cleanup = Cleanup::new(root);
    let defaults = PortableReadLimits::default();
    let cases = [
        PortableReadLimits {
            max_file_bytes: 1,
            ..defaults
        },
        PortableReadLimits {
            max_input_bytes: 1,
            ..defaults
        },
        PortableReadLimits {
            max_files: 1,
            ..defaults
        },
        PortableReadLimits {
            max_selected_bytes: 1,
            ..defaults
        },
    ];
    for (case, limits) in cases.into_iter().enumerate() {
        let source = ReadSource::new(root);
        let result = validate(bucket.inner.config.clone(), &source, limits).await;
        assert!(
            matches!(result, Err(error) if matches!(error.kind(), StoreErrorKind::Capacity)),
            "{case}"
        );
        if case <= 1 {
            assert!(
                source.ranges.lock().unwrap().is_empty(),
                "budget must precede body read"
            );
        }
        assert!(!source.mutations.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn portable_reader_refuses_unavailable_native_capture_without_fallback() {
    let bucket = bucket_tests::fixture().await;
    let _cleanup = Cleanup::new(bucket.root());
    let mut source = ReadSource::new(bucket.root());
    source.decline_capture = true;
    assert!(
        matches!(validate(bucket.inner.config.clone(), &source, PortableReadLimits::default()).await,
        Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported))
    );
    assert!(source.ranges.lock().unwrap().is_empty());
    assert!(!source.mutations.load(Ordering::SeqCst));
}

#[tokio::test]
async fn portable_reader_rechecks_original_inputs_before_returning_snapshot() {
    let bucket = bucket_tests::fixture().await;
    let _cleanup = Cleanup::new(bucket.root());
    let source = ReadSource::new(bucket.root());
    source.change_on_close.store(true, Ordering::SeqCst);
    assert!(
        validate(
            bucket.inner.config.clone(),
            &source,
            PortableReadLimits::default()
        )
        .await
        .is_err()
    );
    assert!(!source.change_on_close.load(Ordering::SeqCst));
    assert!(!source.mutations.load(Ordering::SeqCst));
}

#[tokio::test]
async fn portable_reader_does_not_initialize_missing_roots() {
    let bucket = bucket_tests::fixture().await;
    let _cleanup = Cleanup::new(bucket.root());
    let mut config = bucket.inner.config.clone();
    config.root = config.root.with_extension("absent-portable-reader");
    assert!(!config.root.exists());
    let source = ReadSource::new(&config.root);
    assert!(
        validate(config.clone(), &source, PortableReadLimits::default())
            .await
            .is_err()
    );
    assert!(!config.root.exists());
    assert!(!source.mutations.load(Ordering::SeqCst));
}
