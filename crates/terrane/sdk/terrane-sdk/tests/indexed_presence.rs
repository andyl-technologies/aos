//! Checks committed-index membership against actual native bucket publication.
//!
//! Index membership remains separate from ordinary body verification and grants.

#![cfg(all(feature = "tokio", unix))]

use std::{
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::PathBuf,
};

use terrane_format::{
    bucket::{BucketCapabilities, GenerationManifest},
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
    refs::Locality,
};
use terrane_sdk::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    repository::MetadataValidator,
    store::{
        ChunkPosition, ChunkUpload, ContentStore, ContentUpload, ContentValidator, IndexedContent,
        InvalidReason, LocalFs, MAX_INDEXED_HASHES, MetaUpload, StoreErrorKind, StoreFailure,
        TokioClock, TokioLocalFs,
    },
};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;
type Bucket = FileBucket<TokioLocalFs, TokioClock, MetadataValidator>;

struct Fixture {
    bucket: Bucket,
    parent: PathBuf,
    config: FileBucketConfig,
}

impl Fixture {
    async fn new() -> Result<Self, TestError> {
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-indexed-presence-{suffix}"));
        std::fs::DirBuilder::new().mode(0o700).create(&parent)?;
        let owner = std::fs::symlink_metadata(&parent)?.uid();
        let config = FileBucketConfig {
            root: parent.join("bucket"),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m([42; 32]),
            locality: Locality::default(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
        };
        let bucket = FileBucket::open(
            config.clone(),
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(config.chunk_profile.clone()),
        )
        .await?;
        Ok(Self {
            bucket,
            parent,
            config,
        })
    }

    async fn put(&self, bytes: &[u8]) -> Result<Identity, TestError> {
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes)?;
        let encoded = [vec![0], bytes.to_vec()].concat();
        Ok(self
            .bucket
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: &encoded,
                identity: &identity,
                declared_plaintext_len: bytes.len(),
                position: ChunkPosition::Final,
                profile: &self.config.chunk_profile,
            }))
            .await?)
    }

    async fn reopen(&self) -> Result<Bucket, TestError> {
        Ok(FileBucket::open(
            self.config.clone(),
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(self.config.chunk_profile.clone()),
        )
        .await?)
    }

    fn manifest(&self) -> Result<GenerationManifest, TestError> {
        let capabilities =
            BucketCapabilities::decode(&std::fs::read(self.bucket.root().join("CAPABILITIES"))?)?;
        let generation = capabilities.generation.ok_or("missing index generation")?;
        Ok(GenerationManifest::decode(&std::fs::read(
            self.bucket
                .root()
                .join(format!("objects/index/{generation}/MANIFEST")),
        )?)?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.parent);
    }
}

#[tokio::test]
async fn committed_presence_preserves_hash_order_duplicates_and_metadata_across_reopen()
-> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.put(b"first").await?;
    let second = fixture.put(b"second").await?;
    let node = fixture
        .bucket
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Node,
            &[0xa2, 1, 0, 2, 0x80],
        )?))
        .await?;
    let missing = TERRANE_V1.calculate(IdentityKind::Chunk, b"missing")?;
    let hashes = [
        missing.terrane_v1_digest()?,
        first.terrane_v1_digest()?,
        node.terrane_v1_digest()?,
        first.terrane_v1_digest()?,
        second.terrane_v1_digest()?,
    ];

    let present = fixture.bucket.indexed_presence(&hashes).await?;
    let reopened = fixture.reopen().await?;

    assert_eq!(present, vec![false, true, true, true, true]);
    assert_eq!(reopened.indexed_presence(&hashes).await?, present);
    Ok(())
}

#[tokio::test]
async fn virtual_empty_chunk_without_committed_entry_is_not_index_presence() -> TestResult {
    let fixture = Fixture::new().await?;
    let empty = TERRANE_V1.calculate(IdentityKind::Chunk, b"")?;
    let hash = empty.terrane_v1_digest()?;

    let ordinary = fixture.bucket.has(&[empty]).await?;
    let indexed = fixture.bucket.indexed_presence(&[hash]).await?;

    assert_eq!(ordinary, vec![true]);
    assert_eq!(indexed, vec![false]);
    Ok(())
}

#[tokio::test]
async fn empty_and_excessive_requests_are_decided_before_any_backend_io() -> TestResult {
    let fixture = Fixture::new().await?;
    std::fs::remove_dir_all(&fixture.parent)?;

    let empty = fixture.bucket.indexed_presence(&[]).await?;
    let excessive = fixture
        .bucket
        .indexed_presence(&vec![[0; 32]; MAX_INDEXED_HASHES + 1])
        .await;

    assert!(empty.is_empty());
    assert!(excessive.is_err_and(|error| matches!(
        error.kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload {
            rule_id: "PROTO-10"
        })
    )));
    Ok(())
}

#[tokio::test]
async fn maximum_batch_uses_committed_entries_and_quarantine_removes_presence() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.put(b"first").await?;
    let second = fixture.put(b"second").await?;
    let hashes = vec![first.terrane_v1_digest()?; MAX_INDEXED_HASHES];
    assert_eq!(
        fixture.bucket.indexed_presence(&hashes).await?,
        vec![true; MAX_INDEXED_HASHES]
    );

    fixture.bucket.exclude(&first).await?;

    assert_eq!(
        fixture.bucket.indexed_presence(&hashes).await?,
        vec![false; MAX_INDEXED_HASHES]
    );
    assert_eq!(
        fixture
            .bucket
            .indexed_presence(&[second.terrane_v1_digest()?])
            .await?,
        vec![true]
    );
    assert_eq!(
        fixture.reopen().await?.indexed_presence(&hashes).await?,
        vec![false; MAX_INDEXED_HASHES]
    );
    Ok(())
}

#[tokio::test]
async fn committed_index_presence_does_not_substitute_for_body_verification() -> TestResult {
    let fixture = Fixture::new().await?;
    let identity = fixture.put(b"actual committed bytes").await?;
    let manifest = fixture.manifest()?;
    let inventory = manifest
        .inventory
        .as_ref()
        .ok_or("missing pack inventory")?;
    assert_eq!(inventory.len(), 1);
    let id = terrane_sdk::pack::PackId::from_random_bytes(inventory[0].pack_id);
    let path = fixture.bucket.root().join(id.pack_key());
    let mut bytes = std::fs::read(&path)?;
    *bytes.last_mut().ok_or("missing actual pack body")? ^= 1;
    std::fs::write(path, bytes)?;

    let indexed = fixture
        .bucket
        .indexed_presence(&[identity.terrane_v1_digest()?])
        .await?;
    let ordinary = fixture.bucket.has(std::slice::from_ref(&identity)).await;
    let read = fixture.bucket.get(&identity, None).await;

    assert_eq!(indexed, vec![true]);
    assert!(ordinary.is_err());
    assert!(read.is_err());
    Ok(())
}

#[tokio::test]
async fn malformed_selected_index_returns_no_partial_membership() -> TestResult {
    let fixture = Fixture::new().await?;
    let identity = fixture.put(b"held").await?;
    let manifest = fixture.manifest()?;
    let shard = manifest.shards.first().ok_or("missing selected shard")?;
    let path = fixture.bucket.root().join(format!(
        "objects/index/{}/{}.idx",
        manifest.generation, shard.shard
    ));
    let mut bytes = std::fs::read(&path)?;
    bytes.push(0);
    std::fs::write(path, bytes)?;

    let result = fixture
        .bucket
        .indexed_presence(&[[0; 32], identity.terrane_v1_digest()?])
        .await;

    assert!(result.is_err());
    Ok(())
}

/// Checks the binary pack format before the backend independently verifies members.
struct PackValidator;

impl ContentValidator for PackValidator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        if upload.kind() != IdentityKind::Pack {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        terrane_sdk::pack::PackReader::open(upload.bytes())
            .map(|_| ())
            .map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "PACK-10" }),
                    error,
                )
            })
    }
}

#[tokio::test]
async fn durable_container_inventory_does_not_admit_its_members_to_index_presence() -> TestResult {
    use terrane_sdk::pack::{EntryKind, PackClass, PackId, PackWriter};

    let fixture = Fixture::new().await?;
    let bucket = FileBucket::open(
        fixture.config.clone(),
        TokioLocalFs,
        TokioClock,
        PackValidator,
    )
    .await?;
    let plaintext = b"container bytes without member admission";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    let entropy: [u8; 16] = TokioLocalFs
        .random_bytes(16)
        .await?
        .try_into()
        .map_err(|_| "invalid actual pack entropy length")?;
    let mut writer = PackWriter::new(PackId::from_random_bytes(entropy), PackClass::Data, false);
    writer.append_raw(EntryKind::Chunk, plaintext)?;
    let sealed = writer.seal()?;
    bucket
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Pack,
            sealed.bytes(),
        )?))
        .await?;
    let pack_identity = TERRANE_V1.calculate(IdentityKind::Pack, sealed.bytes())?;
    assert_eq!(bucket.get(&pack_identity, None).await?, sealed.bytes());

    let container_only = fixture
        .bucket
        .indexed_presence(&[identity.terrane_v1_digest()?])
        .await?;
    let inventory = fixture
        .manifest()?
        .inventory
        .ok_or("missing container inventory")?;

    assert_eq!(inventory.len(), 1);
    assert_eq!(container_only, vec![false]);
    assert_eq!(fixture.put(plaintext).await?, identity);
    assert_eq!(
        fixture
            .bucket
            .indexed_presence(&[identity.terrane_v1_digest()?])
            .await?,
        vec![true]
    );
    Ok(())
}
