//! Checks index-only reads under genuine retained native namespace exclusion.
//!
//! These cases publish their setup through the native fixture. The original
//! cases establish held index mechanics; `guarded_file` additionally exercises
//! actual file-scoped repository authorization. No service backend is claimed.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture assertions intentionally panic."
)]

use std::{os::unix::fs::MetadataExt, time::Duration};

use terrane_format::{
    bucket::BucketKey,
    identity::{Identity, IdentityKind, TERRANE_V1},
};

use super::{
    content_tests::{chunk_identity, raw, upload},
    held::SingleHeld,
};
use crate::{
    gc::runner::fixture::{Bucket, Fixture},
    store::{
        ChunkPosition, ContentStore, IndexedContent, LocalFs, MAX_INDEXED_HASHES, StoreErrorKind,
    },
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

mod guarded_file;

async fn stored_chunk() -> (Fixture, Bucket, Identity) {
    let fixture = Fixture::new().await;
    let bucket = fixture.guard().store().clone();
    let plaintext = b"held committed-index observation";
    let identity = chunk_identity(plaintext);
    let encoded = raw(plaintext);
    bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            &fixture.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    (fixture, bucket, identity)
}

#[tokio::test]
async fn held_index_presence_uses_original_exclusion_without_pack_body_reads() {
    let (_fixture, bucket, identity) = stored_chunk().await;
    let hash = identity.terrane_v1_digest().unwrap();
    let missing = chunk_identity(b"not admitted").terrane_v1_digest().unwrap();
    let empty = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let pack = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &hash)
        .unwrap()
        .pack();
    let body_key = BucketKey::parse(&format!(
        "objects/pack/{}/{pack}.pack",
        &pack.to_string()[..2]
    ))
    .unwrap();
    let body = bucket.root().join(body_key.as_str());
    let detached = body.with_extension("detached-test-body");
    let coordination = bucket
        .root()
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let held = SingleHeld::acquire_read_only(&bucket).await.unwrap();

    // Withhold the actual body while preserving its committed Live index row.
    // An accidental get/ordinary-has fallback cannot satisfy this assertion.
    tokio::fs::rename(&body, &detached).await.unwrap();
    assert!(matches!(
        bucket.fs().try_lock_existing_exclusive(&coordination).await,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    let source = held.source();
    let present = tokio::time::timeout(
        OPERATION_TIMEOUT,
        source.indexed_presence(&[missing, hash, empty, hash]),
    )
    .await
    .unwrap()
    .unwrap();
    let destination = held.destination();
    let same = tokio::time::timeout(
        OPERATION_TIMEOUT,
        destination.indexed_presence(&[hash, missing]),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(present, [false, true, false, true]);
    assert_eq!(same, [true, false]);
    assert!(matches!(
        bucket.fs().try_lock_existing_exclusive(&coordination).await,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    tokio::fs::rename(&detached, &body).await.unwrap();
    drop(source);
    drop(destination);
    drop(held);
    assert!(
        bucket
            .fs()
            .try_lock_existing_exclusive(&coordination)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn held_index_presence_bounds_requests_and_refuses_replaced_coordination() {
    let (_fixture, bucket, identity) = stored_chunk().await;
    let hash = identity.terrane_v1_digest().unwrap();
    let held = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let source = held.source();
    let maximum = vec![hash; MAX_INDEXED_HASHES];

    let present = tokio::time::timeout(OPERATION_TIMEOUT, source.indexed_presence(&maximum))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(present, vec![true; MAX_INDEXED_HASHES]);

    let coordination = bucket
        .root()
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let retained = coordination.with_extension("retained-test-lock");
    let original = tokio::fs::metadata(&coordination).await.unwrap();
    tokio::fs::rename(&coordination, &retained).await.unwrap();
    tokio::fs::write(&coordination, []).await.unwrap();
    let replacement = tokio::fs::metadata(&coordination).await.unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (replacement.dev(), replacement.ino())
    );

    // Empty and excessive batches must finish before physical observation.
    assert!(source.indexed_presence(&[]).await.unwrap().is_empty());
    let excessive = source
        .indexed_presence(&vec![hash; MAX_INDEXED_HASHES + 1])
        .await
        .unwrap_err();
    let changed = source.indexed_presence(&[hash]).await.unwrap_err();

    assert!(matches!(excessive.kind(), StoreErrorKind::Invalid(_)));
    assert!(matches!(changed.kind(), StoreErrorKind::Corrupt(_)));
    tokio::fs::remove_file(&coordination).await.unwrap();
    tokio::fs::rename(&retained, &coordination).await.unwrap();
    assert_eq!(source.indexed_presence(&[hash]).await.unwrap(), [true]);
}
