//! Calibrates observations against genuine native content and validator operations.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::{FileBucket, tests::config};
use crate::repository::MetadataValidator;
use crate::store::{
    ChunkPosition, ChunkUpload, ContentStore, ContentUpload, InvalidReason, LocalFs, MetaUpload,
    StoreErrorKind, TokioClock, TokioLocalFs,
};
use terrane_core::identity::TERRANE_V1;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type Bucket = FileBucket<TokioLocalFs, TokioClock, MetadataValidator>;

// The normative empty root is a real canonical Node, rather than opaque bytes
// admitted by the permissive backend-test validator.
const EMPTY_ROOT: &[u8] = &[0xa2, 0x01, 0x00, 0x02, 0x80];

async fn fixture() -> Result<Bucket, TestError> {
    let entropy = TokioLocalFs.random_bytes(16).await?;
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let configuration =
        config(std::env::temp_dir().join(format!("terrane-content-observation-{suffix}")));
    let validator = MetadataValidator::new(configuration.chunk_profile.clone());
    Ok(FileBucket::open(configuration, TokioLocalFs, TokioClock, validator).await?)
}

#[tokio::test]
async fn real_node_reads_share_clone_and_held_decoder_observation() -> Result<(), TestError> {
    let bucket = fixture().await?;
    let counts = bucket.observe_metadata_for_tests()?;
    let clone = bucket.clone();
    assert!(std::sync::Arc::ptr_eq(
        &counts,
        &clone.observe_metadata_for_tests()?
    ));
    let identity = bucket
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Node,
            EMPTY_ROOT,
        )?))
        .await?;
    assert_eq!(counts.snapshot().node_puts, 1);
    assert!(counts.snapshot().node_decodes > 0);

    counts.reset();
    assert_eq!(clone.get(&identity, None).await?, EMPTY_ROOT);
    let exclusion = SingleHeld::acquire(&bucket).await?;
    assert_eq!(
        exclusion.destination().get(&identity, None).await?,
        EMPTY_ROOT
    );
    let measured = counts.snapshot();
    assert_eq!(measured.node_gets, 2);
    assert_eq!(measured.node_puts, 0);
    assert!(measured.node_decodes >= 2);
    assert_eq!(measured.commit_gets, 0);
    assert_eq!(measured.commit_puts, 0);

    drop(exclusion);
    tokio::fs::remove_dir_all(bucket.root()).await?;
    Ok(())
}

#[tokio::test]
async fn missing_node_attempt_precedes_body_decode_and_is_fixture_local() -> Result<(), TestError> {
    let bucket = fixture().await?;
    let independent = fixture().await?;
    let counts = bucket.observe_metadata_for_tests()?;
    let other = independent.observe_metadata_for_tests()?;
    let missing = TERRANE_V1.calculate(IdentityKind::Node, EMPTY_ROOT)?;

    let result = bucket.get(&missing, None).await;
    assert!(
        matches!(result, Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Absent(identity) if identity == &missing))
    );
    assert_eq!(
        counts.snapshot(),
        ContentCounts {
            node_gets: 1,
            ..ContentCounts::default()
        }
    );
    assert_eq!(other.snapshot(), ContentCounts::default());

    let commit = TERRANE_V1.calculate(IdentityKind::Commit, b"missing")?;
    assert!(
        matches!(bucket.get(&commit, None).await, Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Absent(identity) if identity == &commit))
    );
    let invalid = bucket
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Commit,
            b"invalid",
        )?))
        .await;
    assert!(
        matches!(invalid, Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "REF-9" })))
    );
    assert_eq!(counts.snapshot().commit_gets, 1);
    assert_eq!(counts.snapshot().commit_puts, 1);
    assert_eq!(counts.snapshot().node_decodes, 0);

    tokio::fs::remove_dir_all(bucket.root()).await?;
    tokio::fs::remove_dir_all(independent.root()).await?;
    Ok(())
}

#[tokio::test]
async fn deduplicated_node_puts_remain_observable_attempts() -> Result<(), TestError> {
    let bucket = fixture().await?;
    let counts = bucket.observe_metadata_for_tests()?;
    let upload = ContentUpload::Meta(MetaUpload::new(IdentityKind::Node, EMPTY_ROOT)?);
    let identity = bucket.put(upload).await?;
    let selected = tokio::fs::read(bucket.root().join("CAPABILITIES")).await?;

    assert_eq!(bucket.put(upload).await?, identity);
    assert_eq!(
        tokio::fs::read(bucket.root().join("CAPABILITIES")).await?,
        selected
    );
    assert_eq!(counts.snapshot().node_puts, 2);
    assert_eq!(counts.snapshot().node_gets, 0);
    assert!(counts.snapshot().node_decodes >= 2);

    tokio::fs::remove_dir_all(bucket.root()).await?;
    Ok(())
}

#[tokio::test]
async fn real_chunk_reads_share_clone_and_held_observation() -> Result<(), TestError> {
    let bucket = fixture().await?;
    let counts = bucket.observe_metadata_for_tests()?;
    let clone = bucket.clone();
    let plaintext = b"native chunk observation calibration";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(plaintext);
    let admitted = bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &bucket.inner.config.chunk_profile,
        }))
        .await?;
    assert_eq!(admitted, identity);

    counts.reset();
    assert_eq!(clone.get(&identity, None).await?, encoded);
    let exclusion = SingleHeld::acquire(&bucket).await?;
    assert_eq!(exclusion.destination().get(&identity, None).await?, encoded);
    assert_eq!(
        counts.snapshot(),
        ContentCounts {
            chunk_gets: 2,
            ..ContentCounts::default()
        }
    );

    drop(exclusion);
    tokio::fs::remove_dir_all(bucket.root()).await?;
    Ok(())
}

#[tokio::test]
async fn missing_chunk_attempts_share_held_observation_and_remain_fixture_local()
-> Result<(), TestError> {
    let bucket = fixture().await?;
    let independent = fixture().await?;
    let counts = bucket.observe_metadata_for_tests()?;
    let other = independent.observe_metadata_for_tests()?;
    let missing = TERRANE_V1.calculate(IdentityKind::Chunk, b"unadmitted calibration chunk")?;

    let clone_result = bucket.clone().get(&missing, None).await;
    assert!(
        matches!(clone_result, Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Absent(identity) if identity == &missing))
    );
    let exclusion = SingleHeld::acquire(&bucket).await?;
    let held_result = exclusion.destination().get(&missing, None).await;
    assert!(
        matches!(held_result, Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Absent(identity) if identity == &missing))
    );
    assert_eq!(
        counts.snapshot(),
        ContentCounts {
            chunk_gets: 2,
            ..ContentCounts::default()
        }
    );
    assert_eq!(other.snapshot(), ContentCounts::default());

    drop(exclusion);
    tokio::fs::remove_dir_all(bucket.root()).await?;
    tokio::fs::remove_dir_all(independent.root()).await?;
    Ok(())
}
