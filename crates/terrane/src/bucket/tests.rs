//! Exercises file-bucket durability, concurrency, and fail-closed reopening.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::store::{
    ChunkPosition, ChunkRequirement, InvalidReason, MetaUpload, RefCasOutcome, RefLogAppendOutcome,
    RefStore, RefWatch, TokioClock, TokioLocalFs,
};
use terrane_core::refs::{RefLogReason, RefLogRecord, RefRecord};

pub(super) struct Validator;
impl ContentValidator for Validator {
    fn validate_meta(&self, _upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        Ok(())
    }

    fn chunk_requirements(
        &self,
        upload: &MetaUpload<'_>,
    ) -> Result<Vec<ChunkRequirement>, StoreFailure> {
        manifest_requirements(upload, &ChunkProfile::cdc_1m([0; 32]))
    }
}

/// Supplies trusted schema declarations for the configured fixture metadata validator.
///
/// # Errors
/// Rejects malformed manifests and unrepresentable declared chunk lengths.
pub(super) fn manifest_requirements(
    upload: &MetaUpload<'_>,
    profile: &ChunkProfile,
) -> Result<Vec<ChunkRequirement>, StoreFailure> {
    if upload.kind() != terrane_core::identity::IdentityKind::Manifest {
        return Ok(Vec::new());
    }
    let invalid = || {
        StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {
            rule_id: "OBJ-15",
        }))
    };
    let manifest =
        terrane_core::manifest::Manifest::decode(upload.bytes(), profile).map_err(|_| invalid())?;
    let count = manifest.chunks.len();
    manifest
        .chunks
        .iter()
        .enumerate()
        .map(|(position, chunk)| {
            Ok(ChunkRequirement {
                identity: terrane_core::identity::TERRANE_V1
                    .from_digest(terrane_core::identity::IdentityKind::Chunk, &chunk.digest)
                    .map_err(|_| invalid())?,
                declared_plaintext_len: usize::try_from(chunk.length).map_err(|_| invalid())?,
                position: if position + 1 == count {
                    ChunkPosition::Final
                } else {
                    ChunkPosition::NonFinal
                },
                missing_rule_id: "OBJ-15",
            })
        })
        .collect()
}

pub(super) type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

#[cfg(unix)]
pub(super) fn control_path(root: &std::path::Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let hash: String = blake3::hash(root.as_os_str().as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    root.with_file_name(format!(".terrane-control:{hash}"))
}

/// Damages selected capability data while keeping its record digests consistent.
#[cfg(unix)]
pub(super) async fn corrupt_selected_capabilities(
    bucket: &Bucket,
    mutate: impl FnOnce(&mut BucketCapabilities),
) {
    use terrane_core::gc::publication::{PublicationCommit, PublicationTransaction};

    let guard = bucket.exclusive().await.unwrap();
    let selected = bucket.selected_publication_locked().await.unwrap();
    let control = control_path(bucket.root());
    let slot_path = control.join(format!("publication/commits/{}", selected.state.revision));
    let mut commit =
        PublicationCommit::decode(&TokioLocalFs.read_nofollow(&slot_path).await.unwrap()).unwrap();
    let transaction_path = control.join(&commit.transaction_key);
    let mut transaction = PublicationTransaction::decode(
        &TokioLocalFs.read_nofollow(&transaction_path).await.unwrap(),
    )
    .unwrap();
    let row = transaction
        .changes
        .iter_mut()
        .find(|row| row.key == "CAPABILITIES")
        .unwrap();
    let mut capabilities = BucketCapabilities::decode(row.new.as_deref().unwrap()).unwrap();
    mutate(&mut capabilities);
    row.new = Some(capabilities.encode().unwrap());
    let bytes = transaction.encode().unwrap();
    commit.transaction_digest = publication::digest(&bytes);
    tokio::fs::write(transaction_path, bytes).await.unwrap();
    tokio::fs::write(slot_path, commit.encode().unwrap())
        .await
        .unwrap();
    drop(guard);
}

pub(super) async fn fixture() -> Bucket {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-bucket-{suffix}"));
    FileBucket::open(config(root), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap()
}

pub(super) fn config(root: PathBuf) -> FileBucketConfig {
    #[cfg(unix)]
    let operator_uid = {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_OWNER: AtomicU64 = AtomicU64::new(0);
        let number = NEXT_OWNER.fetch_add(1, Ordering::Relaxed);
        let owner = root.parent().unwrap().join(format!(
            ".terrane-test-owner:{}:{number}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&owner)
            .unwrap();
        let uid = std::fs::symlink_metadata(&owner).unwrap().uid();
        std::fs::remove_dir(&owner).unwrap();
        uid
    };
    #[cfg(not(unix))]
    let operator_uid = 0;

    FileBucketConfig {
        root,
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid,
            control: None,
        }),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: ChunkProfile::cdc_1m([0; 32]),
        locality: Locality::default(),
    }
}

pub(super) fn log(record: RefRecord, previous: Option<RefRecord>) -> RefLogRecord {
    RefLogRecord {
        record,
        previous_commit: previous.as_ref().map(|record| record.commit),
        expected_previous: Some(previous),
        committed_previous: None,
        principal: "writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 1,
    }
}

pub(super) trait Selected {
    fn selected(self) -> Self;
}

impl Selected for RefRecord {
    fn selected(mut self) -> Self {
        let mut candidate = self.commit;
        candidate[..8].copy_from_slice(&self.seq.to_be_bytes());
        candidate[8..16].copy_from_slice(&self.writer_epoch.to_be_bytes());
        self.candidate_id = Some(candidate);
        self
    }
}

// Fixtures prepare durable proposals explicitly before exercising the real CAS.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub(super) trait PreparedCas {
    async fn prepared_cas(
        &self,
        name: &str,
        expected: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure>;
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    PreparedCas for FileBucket<F, C, V>
{
    async fn prepared_cas(
        &self,
        name: &str,
        expected: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        let current = self.ref_get(name).await?;
        if current.as_ref() == expected
            && new.candidate_id.is_some()
            && !name.starts_with("refs/tags/")
        {
            self.ref_log_append(name, new.seq, &log(new.clone(), expected.cloned()))
                .await?;
        }
        self.ref_cas(name, expected, new).await
    }
}

#[tokio::test]
async fn live_watch_waits_for_authoritative_ref_publication_and_replays_sequences() {
    let bucket = fixture().await;
    let name = "refs/heads/_/main";
    let mut watch = bucket.ref_watch(name, 1).await.unwrap();
    let timeout = std::time::Duration::from_millis(25);
    assert!(tokio::time::timeout(timeout, watch.next()).await.is_err());

    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    let first_log = log(first.clone(), None);
    bucket.ref_log_append(name, 1, &first_log).await.unwrap();
    assert!(bucket.ref_log_read(name, 1).await.unwrap().is_empty());
    assert!(tokio::time::timeout(timeout, watch.next()).await.is_err());
    bucket.prepared_cas(name, None, &first).await.unwrap();
    assert_eq!(watch.next().await.unwrap(), Some(first_log.clone()));

    let second = first.advance([2; 32], 2).unwrap().selected();
    let second_log = log(second.clone(), Some(first.clone()));
    bucket.ref_log_append(name, 2, &second_log).await.unwrap();
    assert!(tokio::time::timeout(timeout, watch.next()).await.is_err());
    bucket
        .prepared_cas(name, Some(&first), &second)
        .await
        .unwrap();
    assert_eq!(watch.next().await.unwrap(), Some(second_log.clone()));

    let mut resumed = bucket.ref_watch(name, 1).await.unwrap();
    assert_eq!(resumed.next().await.unwrap(), Some(first_log));
    assert_eq!(resumed.next().await.unwrap(), Some(second_log));
    assert!(tokio::time::timeout(timeout, resumed.next()).await.is_err());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
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
    let a = RefRecord::first([1; 32], 1, Locality::default()).selected();
    let b = RefRecord::first([2; 32], 1, Locality::default()).selected();

    let (one, two) = tokio::join!(
        first.prepared_cas("refs/heads/_/main", None, &a),
        second.prepared_cas("refs/heads/_/main", None, &b)
    );
    assert_eq!(
        usize::from(matches!(one.unwrap(), RefCasOutcome::Applied))
            + usize::from(matches!(two.unwrap(), RefCasOutcome::Applied)),
        1
    );
    let current = first.ref_get("refs/heads/_/main").await.unwrap().unwrap();
    assert!(current == a || current == b);
    let next = current.advance([3; 32], 2).unwrap().selected();
    let mut wrong = current.clone();
    wrong.writer_epoch += 1;
    assert_eq!(
        first
            .prepared_cas("refs/heads/_/main", Some(&wrong), &next)
            .await
            .unwrap(),
        RefCasOutcome::Conflict(Some(Box::new(current.clone())))
    );
    assert_eq!(
        first
            .prepared_cas("refs/heads/_/main", Some(&current), &next)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    );

    tokio::fs::remove_dir_all(first.root()).await.unwrap();
}

#[tokio::test]
async fn tags_and_reflogs_never_replace_existing_bytes() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    let second = first.advance([2; 32], 2).unwrap().selected();

    assert_eq!(
        bucket
            .prepared_cas("refs/tags/_/release", None, &first)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    );
    assert!(matches!(
        bucket
            .prepared_cas("refs/tags/_/release", Some(&first), &second)
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
    bucket
        .prepared_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();
    assert_eq!(
        bucket.ref_log_read("refs/heads/_/main", 1).await.unwrap()[0].record,
        first
    );
    assert_eq!(
        bucket
            .ref_log_append(
                "refs/heads/_/main",
                2,
                &log(second.clone(), Some(first.clone()))
            )
            .await
            .unwrap(),
        RefLogAppendOutcome::Appended
    );
    assert!(
        bucket
            .root()
            .join(
                BucketKey::reflog_candidate("refs/heads/_/main", 2, &second.candidate_id.unwrap())
                    .unwrap()
                    .as_str()
            )
            .exists()
    );

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn ref_successors_fence_epoch_home_and_sequence() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 9, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();

    for field in 0..3 {
        let mut bad = first.advance([2; 32], 10).unwrap().selected();
        match field {
            0 => bad.seq += 1,
            1 => bad.writer_epoch = 8,
            _ => bad.home.region = Some("moved".into()),
        }
        assert!(
            bucket
                .prepared_cas("refs/heads/_/main", Some(&first), &bad)
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
    let reopened = FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    assert_eq!(reopened.profile(), bucket.profile());
    assert_ne!(
        tokio::fs::read(root.join("CAPABILITIES")).await.unwrap(),
        b"broken"
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn registered_publication_marker_cannot_authorize_legacy_probe_writes() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let path = root.join("CAPABILITIES");
    let mut record = BucketCapabilities::decode(&tokio::fs::read(&path).await.unwrap()).unwrap();
    record.publication_protocol = Some(1);
    let registered = record.encode().unwrap();
    tokio::fs::write(&path, &registered).await.unwrap();
    tokio::fs::remove_dir_all(control_path(&root))
        .await
        .unwrap();

    let error = FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator)
        .await
        .err()
        .unwrap();

    assert!(matches!(
        error.kind(),
        StoreErrorKind::Unsupported | StoreErrorKind::Unavailable { .. }
    ));
    assert_eq!(tokio::fs::read(&path).await.unwrap(), registered);

    let proposed = RefRecord::first([1; 32], 1, Locality::default()).selected();
    assert!(
        bucket
            .prepared_cas("refs/heads/_/main", None, &proposed)
            .await
            .is_err()
    );
    assert!(bucket.ref_get("refs/heads/_/main").await.is_err());
    assert!(
        !tokio::fs::try_exists(root.join("refs/heads/_/main:record"))
            .await
            .unwrap()
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), registered);
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn stable_exclusion_inode_survives_cas_and_reopen() {
    use std::os::unix::fs::MetadataExt;
    let bucket = fixture().await;
    let path = bucket
        .root()
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let inode = tokio::fs::metadata(&path).await.unwrap().ino();
    let record = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &record)
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
    let record = RefRecord::first([1; 32], 1, Locality::default()).selected();
    for name in [
        "refs/heads/main",
        "refs/heads/_/.",
        "objects/loose/hash",
        "refs/unknown/_/main",
    ] {
        assert!(bucket.prepared_cas(name, None, &record).await.is_err());
    }
    tokio::fs::create_dir_all(bucket.root().join("refs"))
        .await
        .unwrap();
    std::os::unix::fs::symlink(std::env::temp_dir(), bucket.root().join("refs/heads")).unwrap();
    assert!(
        bucket
            .prepared_cas("refs/heads/_/main", None, &record)
            .await
            .is_err()
    );
    assert!(bucket.ref_get("refs/heads/_/main").await.is_err());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn missing_reflog_with_committed_horizon_is_corruption() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();
    let key =
        BucketKey::reflog_candidate("refs/heads/_/main", first.seq, &first.candidate_id.unwrap())
            .unwrap();
    tokio::fs::remove_file(bucket.root().join(key.as_str()))
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
async fn committed_reflog_must_match_the_complete_ref_record() {
    let bucket = fixture().await;
    let pending = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &pending)
        .await
        .unwrap();
    // Damage the exact selected proposal, retaining its selector but changing
    // a whole-record field; an ordinary cache cannot create selected history.
    let mut committed = RefRecord::first([2; 32], 1, Locality::default()).selected();
    committed.candidate_id = pending.candidate_id;
    let key = BucketKey::reflog_candidate(
        "refs/heads/_/main",
        pending.seq,
        &pending.candidate_id.unwrap(),
    )
    .unwrap();
    tokio::fs::write(
        bucket.root().join(key.as_str()),
        log(committed, None).encode().unwrap(),
    )
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
async fn missing_capabilities_cache_recovers_existing_selected_state() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let record = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &record)
        .await
        .unwrap();
    tokio::fs::remove_file(root.join("CAPABILITIES"))
        .await
        .unwrap();

    let reopened = FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    assert_eq!(
        reopened.ref_get("refs/heads/_/main").await.unwrap(),
        Some(record.clone())
    );
    assert_eq!(
        tokio::fs::read(root.join("refs/heads/_/main:record"))
            .await
            .unwrap(),
        record.encode().unwrap()
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}
