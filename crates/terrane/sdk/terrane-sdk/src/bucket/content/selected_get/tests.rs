//! Exercises real ordinary gets across physical and current-selection changes.
//!
//! Pauses follow actual payload verification and precede fresh closing checks.
//! Every input and replacement comes from the isolated native filesystem; tests
//! construct no selected observation, retained recipe or acknowledgment.

mod fallback;
mod grouped;
mod history;

use super::*;
use crate::bucket::content_observation::GetClosePause;
use crate::bucket::tests::{Bucket, control_path, fixture};
use crate::store::{ChunkUpload, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

struct Fixture {
    bucket: Bucket,
    identity: Identity,
    encoded: Vec<u8>,
    pack: PathBuf,
    index: PathBuf,
    shard: PathBuf,
    slot: PathBuf,
}

impl Fixture {
    async fn new() -> Result<Self, TestError> {
        let bucket = fixture().await;
        let plaintext = b"actual ordinary content request physical receipts";
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
        let encoded = raw(plaintext);
        admit(&bucket, &identity, &encoded, plaintext.len()).await?;

        let holder = SingleHeld::acquire_read_only(&bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        let catalog = bucket.catalog_observed(&observed).await?;
        let location = bucket.location(&catalog, &identity)?;
        let pack = bucket.root().join(location.pack().pack_key());
        let index = bucket.root().join(location.pack().index_key());
        let generation = catalog
            .capabilities
            .generation
            .ok_or("no actual generation")?;
        let shard = bucket.root().join(format!(
            "objects/index/{generation}/{}.idx",
            identity.terrane_v1_digest()?[0]
        ));
        let slot = control_path(bucket.root())
            .join(format!("publication/commits/{}", observed.state().revision));
        drop(observed);
        drop(held);
        drop(holder);

        Ok(Self {
            bucket,
            identity,
            encoded,
            pack,
            index,
            shard,
            slot,
        })
    }

    async fn remove(self) -> TestResult {
        tokio::fs::remove_dir_all(control_path(self.bucket.root())).await?;
        tokio::fs::remove_dir_all(self.bucket.root()).await?;
        Ok(())
    }
}

fn raw(plaintext: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(plaintext);
    bytes
}

async fn admit(bucket: &Bucket, identity: &Identity, encoded: &[u8], length: usize) -> TestResult {
    assert_eq!(
        bucket
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded,
                identity,
                declared_plaintext_len: length,
                position: ChunkPosition::Final,
                profile: &bucket.inner.config.chunk_profile,
            }))
            .await?,
        *identity
    );
    Ok(())
}

struct PausedGet {
    pause: Arc<GetClosePause>,
    request: tokio::task::JoinHandle<Result<Vec<u8>, StoreFailure>>,
}

impl PausedGet {
    async fn start<V>(
        bucket: &FileBucket<TokioLocalFs, crate::store::TokioClock, V>,
        identity: &Identity,
    ) -> Result<Self, TestError>
    where
        V: ContentValidator + BucketBinding + 'static,
    {
        Self::start_range(bucket, identity, None).await
    }

    async fn start_range<V>(
        bucket: &FileBucket<TokioLocalFs, crate::store::TokioClock, V>,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Self, TestError>
    where
        V: ContentValidator + BucketBinding + 'static,
    {
        let pause = bucket.observe_content_for_tests().pause_next_get();
        let bucket = bucket.clone();
        let identity = identity.clone();
        let request = tokio::spawn(async move { bucket.get(&identity, range).await });
        if let Err(timeout) =
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.arrived.notified()).await
        {
            request.abort();
            let outcome = request.await;
            return Err(
                format!("real get did not reach closing boundary: {timeout}; {outcome:?}").into(),
            );
        }
        Ok(Self { pause, request })
    }

    async fn finish(self) -> Result<Result<Vec<u8>, StoreFailure>, TestError> {
        self.pause.release.notify_one();
        Ok(self.request.await?)
    }
}

async fn replace_equal(path: &Path) -> TestResult {
    let original = tokio::fs::symlink_metadata(path).await?;
    let bytes = TokioLocalFs.read_nofollow(path).await?;
    let replacement = path.with_extension("replacement");
    TokioLocalFs.write_new(&replacement, &bytes).await?;
    tokio::fs::set_permissions(&replacement, original.permissions()).await?;
    tokio::fs::rename(&replacement, path).await?;

    let current = tokio::fs::symlink_metadata(path).await?;
    assert_ne!(
        (original.dev(), original.ino()),
        (current.dev(), current.ino())
    );
    assert_eq!(TokioLocalFs.read_nofollow(path).await?, bytes);
    Ok(())
}

fn refused(result: Result<Vec<u8>, StoreFailure>) {
    assert!(
        result.is_err(),
        "changed actual input returned bytes: {result:?}"
    );
}

#[tokio::test]
async fn ordinary_get_closes_selected_and_consumed_artifacts() -> TestResult {
    let fixture = Fixture::new().await?;
    let paused = PausedGet::start(&fixture.bucket, &fixture.identity).await?;
    assert_eq!(paused.finish().await??, fixture.encoded);
    assert_eq!(
        fixture.bucket.get(&fixture.identity, None).await?,
        fixture.encoded
    );

    for (path, kind) in [
        (&fixture.pack, IdentityKind::Pack),
        (&fixture.index, IdentityKind::Index),
    ] {
        let bytes = TokioLocalFs.read_nofollow(path).await?;
        let identity = TERRANE_V1.calculate(kind, &bytes)?;
        assert_eq!(fixture.bucket.get(&identity, None).await?, bytes);
    }

    // Public payload modes and initial hardlinks are valid ordinary data.
    // Protected external control records keep their original strict layout.
    let snapshots = {
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        observed
            .physical_reads()
            .iter()
            .filter_map(|read| {
                read.path()
                    .strip_prefix(fixture.bucket.root())
                    .ok()
                    .filter(|path| path.starts_with("publication/snapshots"))
                    .map(|_| read.path().to_path_buf())
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert!(!snapshots.is_empty(), "actual selected snapshots missing");
    for path in [&fixture.pack, &fixture.index, &fixture.shard]
        .into_iter()
        .chain(&snapshots)
    {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).await?;
        let mut alias = path.as_os_str().to_os_string();
        alias.push(".ordinary-link");
        tokio::fs::hard_link(path, PathBuf::from(alias)).await?;
        let metadata = tokio::fs::symlink_metadata(path).await?;
        assert_eq!(metadata.mode() & 0o777, 0o666);
        assert_eq!(metadata.nlink(), 2);
    }
    let parent = fixture.shard.parent().ok_or("actual shard parent absent")?;
    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).await?;
    assert_eq!(
        fixture.bucket.get(&fixture.identity, None).await?,
        fixture.encoded
    );
    assert_eq!(
        fixture
            .bucket
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
    fixture.remove().await?;
    history::check_public_logs().await
}

#[tokio::test]
async fn ordinary_get_refuses_changed_selection_before_return() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let plaintext = b"another genuinely published ordinary content body";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    admit(&fixture.bucket, &identity, &raw(plaintext), plaintext.len()).await?;
    {
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        fixture.slot = control_path(fixture.bucket.root())
            .join(format!("publication/commits/{}", observed.state().revision));
    }
    // Temporarily hide only the last ACTUAL published slot. Restoring its same
    // inode advances selection to genuine already-committed bytes, not a tuple
    // or a transaction assembled by this fixture.
    let pending = fixture.slot.with_extension("held-back");
    tokio::fs::rename(&fixture.slot, &pending).await?;
    let paused = PausedGet::start(&fixture.bucket, &fixture.identity).await?;
    tokio::fs::rename(&pending, &fixture.slot).await?;
    refused(paused.finish().await?);
    fixture.remove().await
}

#[tokio::test]
async fn ordinary_get_refuses_equal_byte_selected_reincarnation() -> TestResult {
    let fixture = Fixture::new().await?;
    let paused = PausedGet::start(&fixture.bucket, &fixture.identity).await?;
    replace_equal(&fixture.slot).await?;
    refused(paused.finish().await?);
    fixture.remove().await
}

#[tokio::test]
async fn ordinary_get_refuses_equal_byte_pack_or_index_reincarnation() -> TestResult {
    for (index, range) in [
        (false, None),
        (true, None),
        (
            false,
            Some(ByteRange {
                start: 1,
                length: 3,
            }),
        ),
        (
            true,
            Some(ByteRange {
                start: 1,
                length: 3,
            }),
        ),
    ] {
        let fixture = Fixture::new().await?;
        let paused = PausedGet::start_range(&fixture.bucket, &fixture.identity, range).await?;
        replace_equal(if index { &fixture.index } else { &fixture.pack }).await?;
        refused(paused.finish().await?);
        fixture.remove().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_get_refuses_changed_catalog_artifact_or_ancestor() -> TestResult {
    for fault in 0..6 {
        let fixture = Fixture::new().await?;
        let paused = PausedGet::start(&fixture.bucket, &fixture.identity).await?;
        if fault >= 4 {
            let path = if fault == 4 {
                fixture.bucket.root().join("CAPABILITIES")
            } else {
                fixture
                    .shard
                    .parent()
                    .ok_or("actual shard parent absent")?
                    .join("MANIFEST")
            };
            let original = path.with_extension("ordinary-original");
            tokio::fs::rename(&path, &original).await?;
            tokio::fs::symlink(&original, &path).await?;
            assert!(
                tokio::fs::symlink_metadata(&path)
                    .await?
                    .file_type()
                    .is_symlink()
            );
        } else if fault == 1 {
            let parent = fixture.shard.parent().ok_or("actual shard parent absent")?;
            let original = tokio::fs::symlink_metadata(parent).await?;
            let old = parent.with_extension("original");
            tokio::fs::rename(parent, &old).await?;
            tokio::fs::create_dir(parent).await?;
            tokio::fs::set_permissions(parent, original.permissions()).await?;
            let mut children = tokio::fs::read_dir(&old).await?;
            while let Some(child) = children.next_entry().await? {
                tokio::fs::rename(child.path(), parent.join(child.file_name())).await?;
            }
            let current = tokio::fs::symlink_metadata(parent).await?;
            assert_ne!(
                (original.dev(), original.ino()),
                (current.dev(), current.ino())
            );
        } else if fault == 2 {
            let parent = fixture.shard.parent().ok_or("actual shard parent absent")?;
            let original = tokio::fs::symlink_metadata(parent).await?;
            let mut permissions = original.permissions();
            permissions.set_mode(0o777);
            tokio::fs::set_permissions(parent, permissions).await?;
            assert_eq!(
                tokio::fs::symlink_metadata(parent).await?.mode() & 0o777,
                0o777
            );
        } else if fault == 3 {
            let link = fixture.shard.with_extension("extra-link");
            tokio::fs::hard_link(&fixture.shard, link).await?;
            assert_eq!(
                tokio::fs::symlink_metadata(&fixture.shard).await?.nlink(),
                2
            );
        } else {
            let mut bytes = TokioLocalFs.read_nofollow(&fixture.shard).await?;
            let first = bytes.first_mut().ok_or("actual merged shard is empty")?;
            *first ^= 1;
            tokio::fs::write(&fixture.shard, &bytes).await?;
        }
        refused(paused.finish().await?);
        fixture.remove().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_get_preserves_ranges_and_corruption_refusals() -> TestResult {
    let fixture = Fixture::new().await?;
    let range = ByteRange {
        start: 2,
        length: 7,
    };
    // This witnesses returned bytes, not STORE-4's separate bounded-I/O gate.
    assert_eq!(
        fixture.bucket.get(&fixture.identity, Some(range)).await?,
        fixture.encoded[2..9]
    );
    for range in [
        ByteRange {
            start: u64::MAX,
            length: 1,
        },
        ByteRange {
            start: 0,
            length: u64::MAX,
        },
    ] {
        let failure = fixture.bucket.get(&fixture.identity, Some(range)).await;
        assert!(
            matches!(failure, Err(ref error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Range(actual)) if actual == &range))
        );
    }
    let mut bytes = TokioLocalFs.read_nofollow(&fixture.pack).await?;
    let last = bytes.last_mut().ok_or("actual pack is empty")?;
    *last ^= 1;
    tokio::fs::write(&fixture.pack, bytes).await?;
    let failure = fixture.bucket.get(&fixture.identity, None).await;
    assert!(
        matches!(failure, Err(ref error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)))
    );
    fixture.remove().await
}

#[tokio::test]
async fn ordinary_get_closes_dictionary_dependency_recipes() -> TestResult {
    let fixture = Fixture::new().await?;
    let dictionary = vec![b'd'; 32768];
    let dictionary_id = TERRANE_V1.calculate(IdentityKind::Chunk, &dictionary)?;
    admit(
        &fixture.bucket,
        &dictionary_id,
        &raw(&dictionary),
        dictionary.len(),
    )
    .await?;
    let plaintext = vec![b'd'; 65536];
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
    let encoded = crate::codec::encode_chunk(
        &plaintext,
        fixture.bucket.inner.config.chunk_profile.maximum(),
        3,
        Some(&dictionary),
    )?;
    assert!(matches!(
        parse_envelope(&encoded)?.codec,
        Codec::ZstdDictionary(_)
    ));
    admit(&fixture.bucket, &identity, &encoded, plaintext.len()).await?;
    let dictionary_pack = {
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        let catalog = fixture.bucket.catalog_observed(&observed).await?;
        fixture.bucket.root().join(
            fixture
                .bucket
                .location(&catalog, &dictionary_id)?
                .pack()
                .pack_key(),
        )
    };

    let paused = PausedGet::start(&fixture.bucket, &identity).await?;
    replace_equal(&dictionary_pack).await?;
    refused(paused.finish().await?);
    let range = ByteRange {
        start: 1,
        length: 5,
    };
    assert_eq!(
        fixture.bucket.get(&identity, Some(range)).await?,
        encoded[1..6]
    );
    let paused = PausedGet::start_range(&fixture.bucket, &identity, Some(range)).await?;
    replace_equal(&dictionary_pack).await?;
    refused(paused.finish().await?);
    fixture.remove().await
}

#[tokio::test]
async fn ordinary_get_cancellation_retains_no_request_authority() -> TestResult {
    let fixture = Fixture::new().await?;
    let paused = PausedGet::start(&fixture.bucket, &fixture.identity).await?;
    paused.request.abort();
    assert!(paused.request.await.is_err());

    // A later call must acquire a new actual exclusion and consume current
    // bytes. There is no completed DATA or authority carrier to reuse.
    replace_equal(&fixture.pack).await?;
    assert_eq!(
        fixture.bucket.get(&fixture.identity, None).await?,
        fixture.encoded
    );
    let mut bytes = TokioLocalFs.read_nofollow(&fixture.pack).await?;
    let last = bytes.last_mut().ok_or("actual pack is empty")?;
    *last ^= 1;
    tokio::fs::write(&fixture.pack, bytes).await?;
    refused(fixture.bucket.get(&fixture.identity, None).await);
    fixture.remove().await
}

#[tokio::test]
async fn ordinary_get_preserves_legacy_and_unretained_fallback() -> TestResult {
    fallback::check().await
}
