//! Exercises genuine administrative writer refusal and retained reader lifetimes.

#![allow(
    clippy::unwrap_used,
    reason = "native fixture failures are intended test panics"
)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

use super::{ControlAccess, ControlExclusion};
use crate::bucket::held::SingleHeld;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::repository::local_authority::retention::{
    self, BootstrapRecord, Record, configuration_lock,
};
use crate::repository::{Error, MetadataValidator};
use crate::store::{LocalFs, StoreErrorKind, TokioClock, TokioLocalFs};
use terrane_format::bucket::BucketKey;
use terrane_format::chunking::ChunkProfile;
use terrane_format::refs::Locality;

struct Fixture {
    parent: PathBuf,
    directory: PathBuf,
    bucket: FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
    namespace_lock: PathBuf,
    owner: u32,
    original: BootstrapRecord,
}

impl Fixture {
    async fn new() -> Self {
        let nonce = TokioLocalFs.random_bytes(16).await.unwrap();
        let parent = std::env::temp_dir().join(format!(
            "terrane-original-lock-mode-{}",
            blake3::hash(&nonce).to_hex()
        ));
        TokioLocalFs.create_dir_new(&parent).await.unwrap();
        TokioLocalFs
            .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let directory = parent.join("original");
        TokioLocalFs.create_dir_new(&directory).await.unwrap();
        let owner = TokioLocalFs
            .symlink_metadata(&directory)
            .await
            .unwrap()
            .uid();
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: parent.join("bucket"),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: profile.clone(),
                locality: Locality::default(),
            },
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(profile),
        )
        .await
        .unwrap();
        let registration = retention::initialize_registration(
            &TokioLocalFs,
            bucket.root(),
            "public",
            &directory,
            owner,
        )
        .await
        .unwrap();
        let namespace_lock = bucket
            .root()
            .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
        let namespace = SingleHeld::acquire(&bucket).await.unwrap();
        let controls = configuration_lock(&TokioLocalFs, &directory, owner, false)
            .await
            .unwrap();
        let original = BootstrapRecord {
            id: registration.id,
            reference: "refs/heads/_/main".into(),
            epoch: 1,
            acl: vec![("writer".into(), 31)],
        };
        retention::retain(
            &TokioLocalFs,
            &directory,
            owner,
            &original.selector().unwrap(),
            &original,
            false,
        )
        .await
        .unwrap();
        drop(controls);
        drop(namespace);

        Self {
            parent,
            directory,
            bucket,
            namespace_lock,
            owner,
            original,
        }
    }

    async fn acquire(&self, access: ControlAccess) -> ControlExclusion<'_, TokioLocalFs> {
        let _namespace = SingleHeld::acquire(&self.bucket).await.unwrap();
        ControlExclusion::acquire(&TokioLocalFs, &self.directory, self.owner, access)
            .await
            .unwrap()
    }

    /// Uses the actual writer API beneath genuine exclusive namespace acquisition.
    async fn write(&self, record: &BootstrapRecord) -> Result<(), Error> {
        let _namespace = SingleHeld::acquire(&self.bucket).await?;
        let _controls =
            configuration_lock(&TokioLocalFs, &self.directory, self.owner, false).await?;
        retention::retain(
            &TokioLocalFs,
            &self.directory,
            self.owner,
            &record.selector()?,
            record,
            false,
        )
        .await
    }

    async fn remove(self) {
        drop(self.bucket);
        tokio::fs::remove_dir_all(self.parent).await.unwrap();
    }
}

#[tokio::test]
async fn original_retained_readers_refuse_actual_writer_and_release_namespace() {
    let fixture = Fixture::new().await;
    let mut first = fixture.acquire(ControlAccess::Read).await;
    let second = fixture.acquire(ControlAccess::Read).await;
    let selector = fixture.original.selector().unwrap();
    let receipt = first
        .retain_named(&[(selector.clone(), fixture.original.encode().unwrap())])
        .await
        .unwrap();
    // The native worker retention API keeps these actual acquired duplicates.
    // Logical receipt release must not discharge their shared read lock.
    let worker_exclusions = receipt.exclusions();
    let mut first = Some(first);
    let mut second = Some(second);
    let mut new_record = fixture.original.clone();
    new_record.epoch = 2;
    let new_path = fixture.directory.join(new_record.selector().unwrap());

    for release in 0..3 {
        match release {
            1 => drop(first.take()),
            2 => drop(second.take()),
            _ => {}
        }
        let result = tokio::time::timeout(Duration::from_secs(5), fixture.write(&new_record))
            .await
            .unwrap();
        let Err(Error::Store(failure)) = result else {
            panic!("actual administrative writer must refuse a retained reader");
        };
        assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
        assert!(!new_path.exists());
        // Successful fresh exclusive acquisition proves the refused writer
        // released its namespace instead of retaining it while awaiting controls.
        let namespace = TokioLocalFs
            .try_lock_existing_exclusive(&fixture.namespace_lock)
            .await
            .unwrap();
        drop(namespace);
    }
    drop(first);
    drop(second);
    drop(receipt);
    let result = fixture.write(&new_record).await;
    assert!(matches!(
        result,
        Err(Error::Store(ref failure)) if matches!(failure.kind(), StoreErrorKind::Unavailable { .. })
    ));
    assert!(!new_path.exists());

    drop(worker_exclusions);
    fixture.write(&new_record).await.unwrap();
    let reopened: BootstrapRecord = retention::read(
        &TokioLocalFs,
        &fixture.directory,
        fixture.owner,
        &new_record.selector().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(reopened, new_record);
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&fixture.directory.join(selector))
            .await
            .unwrap(),
        fixture.original.encode().unwrap()
    );
    fixture.remove().await;
}

#[tokio::test]
async fn original_read_and_write_attempts_refuse_live_writer_without_waiting() {
    let fixture = Fixture::new().await;
    let writer = fixture.acquire(ControlAccess::Write).await;
    for access in [ControlAccess::Read, ControlAccess::Write] {
        let namespace = TokioLocalFs
            .lock_existing_exclusive(&fixture.namespace_lock)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            ControlExclusion::acquire(&TokioLocalFs, &fixture.directory, fixture.owner, access),
        )
        .await
        .unwrap();
        let Err(failure) = result else {
            panic!("live administrative writer must exclude a new control attempt");
        };
        assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
        drop(namespace);
    }
    drop(writer);

    let mut reader = fixture.acquire(ControlAccess::Read).await;
    assert_eq!(
        reader
            .read_record(&fixture.original.selector().unwrap())
            .await
            .unwrap(),
        fixture.original.encode().unwrap()
    );
    drop(reader);
    let writer = fixture.acquire(ControlAccess::Write).await;
    drop(writer);
    fixture.remove().await;
}
