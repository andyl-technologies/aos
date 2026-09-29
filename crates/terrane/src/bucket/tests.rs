//! Exercises file-bucket durability, concurrency, and fail-closed reopening.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::store::{
    MetaUpload, RefCasOutcome, RefLogAppendOutcome, RefStore, TokioClock, TokioLocalFs,
};
use terrane_core::refs::{RefLogReason, RefLogRecord, RefRecord};

pub(super) struct Validator;
impl ContentValidator for Validator {
    fn validate_meta(&self, _upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        Ok(())
    }
}

type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

async fn fixture() -> Bucket {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-bucket-{suffix}"));
    FileBucket::open(config(root), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap()
}

pub(super) fn config(root: PathBuf) -> FileBucketConfig {
    FileBucketConfig {
        root,
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: ChunkProfile::cdc_1m([0; 32]),
        locality: Locality::default(),
    }
}

fn log(record: RefRecord, previous_commit: Option<[u8; 32]>) -> RefLogRecord {
    RefLogRecord {
        record,
        previous_commit,
        principal: "writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 1,
    }
}

#[tokio::test]
async fn whole_record_cas_has_one_winner_across_independent_opens() {
    let first = fixture().await;
    let second = FileBucket::open(
        config(first.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let a = RefRecord::first([1; 32], 1, Locality::default());
    let b = RefRecord::first([2; 32], 1, Locality::default());

    let (one, two) = tokio::join!(
        first.ref_cas("refs/heads/_/main", None, &a),
        second.ref_cas("refs/heads/_/main", None, &b)
    );
    assert_eq!(
        usize::from(matches!(one.unwrap(), RefCasOutcome::Applied))
            + usize::from(matches!(two.unwrap(), RefCasOutcome::Applied)),
        1
    );
    let current = first.ref_get("refs/heads/_/main").await.unwrap().unwrap();
    assert!(current == a || current == b);
    let next = current.advance([3; 32], 2).unwrap();
    let mut wrong = current.clone();
    wrong.writer_epoch += 1;
    assert_eq!(
        first
            .ref_cas("refs/heads/_/main", Some(&wrong), &next)
            .await
            .unwrap(),
        RefCasOutcome::Conflict(Some(Box::new(current.clone())))
    );
    assert_eq!(
        first
            .ref_cas("refs/heads/_/main", Some(&current), &next)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    );

    tokio::fs::remove_dir_all(first.root()).await.unwrap();
}

#[tokio::test]
async fn tags_and_reflogs_never_replace_existing_bytes() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 1, Locality::default());
    let second = first.advance([2; 32], 2).unwrap();

    assert_eq!(
        bucket
            .ref_cas("refs/tags/_/release", None, &first)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    );
    assert!(matches!(
        bucket
            .ref_cas("refs/tags/_/release", Some(&first), &second)
            .await
            .unwrap(),
        RefCasOutcome::Conflict(_)
    ));
    assert_eq!(
        bucket.ref_get("refs/tags/_/release").await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        bucket
            .ref_log_append("refs/heads/_/main", 1, &log(first.clone(), None))
            .await
            .unwrap(),
        RefLogAppendOutcome::Appended
    );
    let mut replacement = first.clone();
    replacement.commit = [9; 32];
    assert_eq!(
        bucket
            .ref_log_append("refs/heads/_/main", 1, &log(replacement, None))
            .await
            .unwrap(),
        RefLogAppendOutcome::Exists
    );
    assert_eq!(
        bucket.ref_log_read("refs/heads/_/main", 1).await.unwrap()[0].record,
        first
    );
    assert_eq!(
        bucket
            .ref_log_append("refs/heads/_/main", 2, &log(second, Some(first.commit)))
            .await
            .unwrap(),
        RefLogAppendOutcome::Appended
    );
    assert!(
        bucket
            .root()
            .join("logs/refs/heads/_/main/00000000000000000002")
            .exists()
    );

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn ref_successors_fence_epoch_home_and_sequence() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 9, Locality::default());
    bucket
        .ref_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();

    for field in 0..3 {
        let mut bad = first.advance([2; 32], 10).unwrap();
        match field {
            0 => bad.seq += 1,
            1 => bad.writer_epoch = 8,
            _ => bad.home.region = Some("moved".into()),
        }
        assert!(
            bucket
                .ref_cas("refs/heads/_/main", Some(&first), &bad)
                .await
                .is_err()
        );
    }
    assert_eq!(
        bucket.ref_get("refs/heads/_/main").await.unwrap(),
        Some(first)
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn probe_revalidates_persisted_layout_and_profile_each_open() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    assert_eq!(bucket.capabilities().refs, RefCapability::Cas);
    let record =
        BucketCapabilities::decode(&tokio::fs::read(root.join("CAPABILITIES")).await.unwrap())
            .unwrap();
    assert!(record.create_if_absent && record.compare_and_swap && record.ranges);
    assert!(!record.presign);

    let mut incompatible = config(root.clone());
    incompatible.chunk_profile = ChunkProfile::cdc_1m([1; 32]);
    assert!(
        FileBucket::open(incompatible, TokioLocalFs, TokioClock, Validator)
            .await
            .is_err()
    );
    tokio::fs::write(root.join("CAPABILITIES"), b"broken")
        .await
        .unwrap();
    assert!(
        FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator)
            .await
            .is_err()
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn stable_exclusion_inode_survives_cas_and_reopen() {
    use std::os::unix::fs::MetadataExt;
    let bucket = fixture().await;
    let path = bucket.root().join(".terrane-lock");
    let inode = tokio::fs::metadata(&path).await.unwrap().ino();
    let record = RefRecord::first([1; 32], 1, Locality::default());
    bucket
        .ref_cas("refs/heads/_/main", None, &record)
        .await
        .unwrap();
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(tokio::fs::metadata(&path).await.unwrap().ino(), inode);
    assert_eq!(
        reopened.ref_get("refs/heads/_/main").await.unwrap(),
        Some(record)
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn unknown_keys_are_not_refs_and_symlinks_fail_closed() {
    let bucket = fixture().await;
    let record = RefRecord::first([1; 32], 1, Locality::default());
    for name in [
        "refs/heads/main",
        "refs/heads/_/.",
        "objects/loose/hash",
        "refs/unknown/_/main",
    ] {
        assert!(bucket.ref_cas(name, None, &record).await.is_err());
    }
    tokio::fs::create_dir_all(bucket.root().join("refs"))
        .await
        .unwrap();
    std::os::unix::fs::symlink(std::env::temp_dir(), bucket.root().join("refs/heads")).unwrap();
    assert!(
        bucket
            .ref_cas("refs/heads/_/main", None, &record)
            .await
            .is_err()
    );
    assert!(bucket.ref_get("refs/heads/_/main").await.is_err());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn missing_reflog_with_committed_horizon_is_corruption() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 1, Locality::default());
    bucket
        .ref_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();
    assert!(matches!(
        bucket
            .ref_log_read("refs/heads/_/main", 1)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn missing_capabilities_never_reinitializes_existing_portable_state() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let record = RefRecord::first([1; 32], 1, Locality::default());
    bucket.ref_cas("refs/heads/_/main", None, &record).await.unwrap();
    tokio::fs::remove_file(root.join("CAPABILITIES")).await.unwrap();

    assert!(FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator).await.is_err());
    assert_eq!(tokio::fs::read(root.join("refs/heads/_/main")).await.unwrap(), record.encode().unwrap());
    tokio::fs::remove_dir_all(root).await.unwrap();
}
