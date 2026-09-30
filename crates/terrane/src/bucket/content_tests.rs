//! Exercises concrete content admission, dedup, verified ranges, and publication.

#![allow(clippy::unwrap_used)]

use super::tests::{Validator, config};
use super::*;
use crate::store::{
    ByteRange, ChunkPosition, ChunkUpload, ContentStore, ContentUpload, IdentityPrefix,
    InvalidReason, MetaUpload, TokioClock, TokioLocalFs,
};
use std::collections::BTreeMap;
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_core::manifest::{ChunkRef, Manifest};

pub(super) async fn fixture() -> FileBucket<TokioLocalFs, TokioClock, Validator> {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-bucket-content-{suffix}"));
    FileBucket::open(config(root), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap()
}

pub(super) fn chunk_identity(bytes: &[u8]) -> Identity {
    TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap()
}

pub(super) fn raw(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0];
    encoded.extend_from_slice(bytes);
    encoded
}

pub(super) fn upload<'a>(
    encoded: &'a [u8],
    identity: &'a Identity,
    length: usize,
    profile: &'a ChunkProfile,
    position: ChunkPosition,
) -> ContentUpload<'a> {
    ContentUpload::Chunk(ChunkUpload {
        encoded,
        identity,
        declared_plaintext_len: length,
        position,
        profile,
    })
}

#[tokio::test]
async fn repeated_put_preserves_first_encoding_and_survives_reopen() {
    let bucket = fixture().await;
    let plaintext = vec![b'x'; 32768];
    let identity = chunk_identity(&plaintext);
    let encoded = raw(&plaintext);
    let profile = &bucket.inner.config.chunk_profile;
    bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let before = tokio::fs::read(bucket.root().join("CAPABILITIES"))
        .await
        .unwrap();
    let compressed = crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, None).unwrap();
    assert_ne!(compressed, encoded);

    assert_eq!(
        bucket
            .put(upload(
                &compressed,
                &identity,
                plaintext.len(),
                profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap(),
        identity
    );
    assert_eq!(bucket.get(&identity, None).await.unwrap(), encoded);
    assert_eq!(
        tokio::fs::read(bucket.root().join("CAPABILITIES"))
            .await
            .unwrap(),
        before
    );
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.get(&identity, None).await.unwrap(), encoded);
    assert_eq!(
        BucketCapabilities::decode(&before).unwrap().generation,
        reopened.catalog().await.unwrap().capabilities.generation
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn admission_validates_identity_length_profile_and_independent_dedup_context() {
    let bucket = fixture().await;
    let bytes = b"short final chunk";
    let identity = chunk_identity(bytes);
    let encoded = raw(bytes);
    let profile = &bucket.inner.config.chunk_profile;
    bucket
        .put(upload(
            &encoded,
            &identity,
            bytes.len(),
            profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();

    for offer in [
        upload(
            &encoded,
            &identity,
            bytes.len(),
            profile,
            ChunkPosition::NonFinal,
        ),
        upload(
            &encoded,
            &identity,
            bytes.len() + 1,
            profile,
            ChunkPosition::Final,
        ),
        upload(&[9], &identity, bytes.len(), profile, ChunkPosition::Final),
    ] {
        assert!(bucket.put(offer).await.is_err());
    }
    let wrong = chunk_identity(b"other plaintext");
    assert!(
        bucket
            .put(upload(
                &encoded,
                &wrong,
                bytes.len(),
                profile,
                ChunkPosition::Final
            ))
            .await
            .is_err()
    );
    let other_profile = ChunkProfile::cdc_1m([1; 32]);
    assert!(
        bucket
            .put(upload(
                &encoded,
                &identity,
                bytes.len(),
                &other_profile,
                ChunkPosition::Final
            ))
            .await
            .is_err()
    );

    let boundary_bytes = vec![7; profile.minimum() + 1];
    assert!(!profile.valid_nonfinal_chunk(&boundary_bytes));
    let boundary_id = chunk_identity(&boundary_bytes);
    let boundary_encoded = raw(&boundary_bytes);
    bucket
        .put(upload(
            &boundary_encoded,
            &boundary_id,
            boundary_bytes.len(),
            profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let error = bucket
        .put(upload(
            &boundary_encoded,
            &boundary_id,
            boundary_bytes.len(),
            profile,
            ChunkPosition::NonFinal,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-16" })
    ));
    assert_eq!(bucket.get(&identity, None).await.unwrap(), encoded);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn corrupt_bytes_outside_requested_range_are_never_returned() {
    let bucket = fixture().await;
    let plaintext = b"verified complete body";
    let identity = chunk_identity(plaintext);
    let encoded = raw(plaintext);
    bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let location = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == identity.digest())
        .unwrap();
    let path = bucket.root().join(location.pack().pack_key());
    let mut bytes = tokio::fs::read(&path).await.unwrap();
    let offset = location.entry().offset() as usize;
    bytes[offset + encoded.len() - 1] ^= 1;
    tokio::fs::write(&path, bytes).await.unwrap();

    for range in [
        None,
        Some(ByteRange {
            start: 0,
            length: 1,
        }),
    ] {
        assert!(matches!(
            bucket.get(&identity, range).await.unwrap_err().kind(),
            StoreErrorKind::Corrupt(_)
        ));
    }
    assert!(bucket.has(&[identity]).await.is_err());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn ranges_address_verified_encoded_bytes_and_check_overflow() {
    let bucket = fixture().await;
    let plaintext = b"range payload";
    let identity = chunk_identity(plaintext);
    let encoded = raw(plaintext);
    bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();

    assert_eq!(
        bucket
            .get(
                &identity,
                Some(ByteRange {
                    start: 1,
                    length: 5
                })
            )
            .await
            .unwrap(),
        b"range"
    );
    assert!(
        bucket
            .get(
                &identity,
                Some(ByteRange {
                    start: encoded.len() as u64,
                    length: 0
                })
            )
            .await
            .unwrap()
            .is_empty()
    );
    for range in [
        ByteRange {
            start: 0,
            length: encoded.len() as u64 + 1,
        },
        ByteRange {
            start: u64::MAX,
            length: 1,
        },
    ] {
        assert_eq!(
            bucket.get(&identity, Some(range)).await.unwrap_err().kind(),
            &StoreErrorKind::Invalid(InvalidReason::Range(range))
        );
    }
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn batched_membership_preserves_order_duplicates_and_virtual_empty_chunk() {
    let bucket = fixture().await;
    let plaintext = b"held";
    let held = chunk_identity(plaintext);
    bucket
        .put(upload(
            &raw(plaintext),
            &held,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let missing = chunk_identity(b"missing");
    let empty = chunk_identity(b"");

    assert_eq!(
        bucket
            .has(&[missing, held.clone(), empty.clone(), held])
            .await
            .unwrap(),
        vec![false, true, true, true]
    );
    assert_eq!(bucket.get(&empty, None).await.unwrap(), vec![0]);
    assert!(bucket.has(&[]).await.unwrap().is_empty());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn manifest_and_every_listed_artifact_are_required_for_generation_visibility() {
    let bucket = fixture().await;
    let plaintext = b"generation body";
    let identity = chunk_identity(plaintext);
    bucket
        .put(upload(
            &raw(plaintext),
            &identity,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let generation = bucket
        .catalog()
        .await
        .unwrap()
        .capabilities
        .generation
        .unwrap();
    let manifest_path = bucket
        .root()
        .join(format!("objects/index/{generation}/MANIFEST"));
    let manifest = tokio::fs::read(&manifest_path).await.unwrap();
    tokio::fs::remove_file(&manifest_path).await.unwrap();

    assert!(bucket.get(&identity, None).await.is_err());
    assert!(
        FileBucket::open(
            config(bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator
        )
        .await
        .is_err()
    );
    tokio::fs::write(&manifest_path, &manifest).await.unwrap();
    let decoded = terrane_core::bucket::GenerationManifest::decode(&manifest).unwrap();
    let shard = bucket.root().join(format!(
        "objects/index/{generation}/{}.idx",
        decoded.shards[0].shard
    ));
    let mut broken = tokio::fs::read(&shard).await.unwrap();
    broken.push(0);
    tokio::fs::write(&shard, broken).await.unwrap();
    assert!(bucket.has(&[identity]).await.is_err());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

struct SchemaValidator {
    profile: ChunkProfile,
    calls: std::sync::atomic::AtomicUsize,
}

impl ContentValidator for SchemaValidator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if upload.kind() == IdentityKind::Manifest {
            Manifest::decode(upload.bytes(), &self.profile).map_err(|_| {
                StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {
                    rule_id: "OBJ-15",
                }))
            })?;
        }
        Ok(())
    }
}

#[tokio::test]
async fn configured_schema_validator_rejects_canonical_but_invalid_meta() {
    let fixture = fixture().await;
    let root = fixture.root().to_owned();
    let config = config(root.clone());
    let validator = SchemaValidator {
        profile: config.chunk_profile.clone(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let bucket = FileBucket::open(config, TokioLocalFs, TokioClock, validator)
        .await
        .unwrap();
    let bad = MetaUpload::new(IdentityKind::Manifest, &[0xa0]).unwrap();

    let error = bucket.put(ContentUpload::Meta(bad)).await.unwrap_err();
    assert!(matches!(
        error.kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "OBJ-15" })
    ));
    assert!(
        bucket
            .catalog()
            .await
            .unwrap()
            .capabilities
            .generation
            .is_none()
    );

    let size = bucket.inner.config.chunk_profile.minimum() as u64 + 1;
    let plaintext = vec![2; size as usize];
    let chunk_id = chunk_identity(&plaintext);
    bucket
        .put(upload(
            &raw(&plaintext),
            &chunk_id,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let manifest = Manifest {
        size,
        chunks: vec![ChunkRef {
            digest: chunk_id.terrane_v1_digest().unwrap(),
            length: size,
        }],
        hashes: BTreeMap::from([("blake3".into(), vec![2; 32])]),
        media_type: None,
    };
    let bytes = manifest.encode(&bucket.inner.config.chunk_profile).unwrap();
    let identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &bytes).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(bucket.get(&identity, None).await.unwrap(), bytes);
    assert_eq!(
        bucket
            .inner
            .validator
            .calls
            .load(std::sync::atomic::Ordering::Relaxed),
        3
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn dictionaries_are_fetched_by_verified_chunk_identity_before_decode() {
    let bucket = fixture().await;
    let dictionary = vec![b'd'; 32768];
    let dictionary_id = chunk_identity(&dictionary);
    bucket
        .put(upload(
            &raw(&dictionary),
            &dictionary_id,
            dictionary.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let plaintext = vec![b'd'; 65536];
    let identity = chunk_identity(&plaintext);
    let encoded = crate::codec::encode_chunk(
        &plaintext,
        bucket.inner.config.chunk_profile.maximum(),
        3,
        Some(&dictionary),
    )
    .unwrap();
    assert_eq!(encoded[0], 2);

    bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    assert_eq!(bucket.get(&identity, None).await.unwrap(), encoded);
    let prefix = IdentityPrefix {
        kind: IdentityKind::Chunk,
        digest_prefix: Vec::new(),
    };
    assert_eq!(bucket.list(&prefix).await.unwrap().len(), 2);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn portable_copy_reopens_as_the_same_bucket_layout() {
    let bucket = fixture().await;
    let plaintext = b"portable sealed body";
    let identity = chunk_identity(plaintext);
    bucket
        .put(upload(
            &raw(plaintext),
            &identity,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let record = terrane_core::refs::RefRecord::first([1; 32], 1, Locality::default());
    crate::store::RefStore::ref_cas(&bucket, "refs/heads/tenant/main", None, &record)
        .await
        .unwrap();
    let destination = bucket.root().with_extension("copy");
    let mut pending = vec![(bucket.root().to_owned(), destination.clone())];

    while let Some((source, target)) = pending.pop() {
        tokio::fs::create_dir_all(&target).await.unwrap();
        let mut entries = tokio::fs::read_dir(&source).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let output = target.join(entry.file_name());
            if entry.file_type().await.unwrap().is_dir() {
                pending.push((entry.path(), output));
            } else {
                tokio::fs::copy(entry.path(), output).await.unwrap();
            }
        }
    }
    let copied = FileBucket::open(
        config(destination.clone()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(copied.get(&identity, None).await.unwrap(), raw(plaintext));
    assert_eq!(
        crate::store::RefStore::ref_get(&copied, "refs/heads/tenant/main")
            .await
            .unwrap(),
        Some(record)
    );
    assert_eq!(
        copied.catalog().await.unwrap().capabilities.generation,
        bucket.catalog().await.unwrap().capabilities.generation
    );
    tokio::fs::remove_dir_all(destination).await.unwrap();
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}
