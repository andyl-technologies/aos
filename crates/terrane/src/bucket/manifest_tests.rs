//! Exercises manifest reference contexts and optional container inventory.

#![allow(clippy::unwrap_used)]

use super::content_tests::{chunk_identity, fixture, raw, upload};
use super::tests::{Validator, config};
use super::*;
use crate::store::{
    ChunkPosition, ContentStore, ContentUpload, InvalidReason, MetaUpload, TokioClock, TokioLocalFs,
};
use std::collections::BTreeMap;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::manifest::{ChunkRef, Manifest};

mod canonical_final;

#[tokio::test]
async fn manifest_references_accept_an_honest_nonfinal_boundary_and_verified_lengths() {
    let bucket = fixture().await;
    let profile = &bucket.inner.config.chunk_profile;
    let candidate = vec![7; profile.maximum()];
    let first = &candidate[..profile.first_boundary(&candidate)];
    assert!(profile.valid_nonfinal_chunk(first));
    let last = b"last";
    let first_id = chunk_identity(first);
    let last_id = chunk_identity(last);
    for (bytes, identity) in [(first, &first_id), (last.as_slice(), &last_id)] {
        bucket
            .put(upload(
                &raw(bytes),
                identity,
                bytes.len(),
                profile,
                ChunkPosition::Final,
            ))
            .await
            .unwrap();
    }

    let manifest = Manifest {
        size: (first.len() + last.len()) as u64,
        chunks: vec![
            ChunkRef {
                digest: first_id.terrane_v1_digest().unwrap(),
                length: first.len() as u64,
            },
            ChunkRef {
                digest: last_id.terrane_v1_digest().unwrap(),
                length: last.len() as u64,
            },
        ],
        hashes: BTreeMap::from([("blake3".into(), vec![0; 32])]),
        media_type: None,
    };
    let bytes = manifest.encode(profile).unwrap();
    let upload = MetaUpload::new(IdentityKind::Manifest, &bytes).unwrap();
    let identity = bucket.put(ContentUpload::Meta(upload)).await.unwrap();
    let before = bucket.catalog().await.unwrap().capabilities.generation;
    assert_eq!(
        bucket.put(ContentUpload::Meta(upload)).await.unwrap(),
        identity
    );
    assert_eq!(
        bucket.catalog().await.unwrap().capabilities.generation,
        before
    );
    assert_eq!(bucket.get(&identity, None).await.unwrap(), bytes);

    let mut wrong = manifest;
    wrong.size -= 1;
    wrong.chunks[1].length -= 1;
    let bytes = wrong.encode(profile).unwrap();
    let error = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &bytes).unwrap(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-12" })
    ));
    assert_eq!(
        bucket.catalog().await.unwrap().capabilities.generation,
        before
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn publishing_after_a_legacy_manifest_preserves_existing_bodies() {
    let bucket = fixture().await;
    let original = b"existing catalog body";
    let original_id = chunk_identity(original);
    bucket
        .put(upload(
            &raw(original),
            &original_id,
            original.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();

    let catalog = bucket.catalog().await.unwrap();
    let generation = catalog.capabilities.generation.unwrap();
    let path = bucket
        .root()
        .join(format!("objects/index/{generation}/MANIFEST"));
    let selected_manifest = tokio::fs::read(&path).await.unwrap();
    let mut manifest =
        terrane_core::bucket::GenerationManifest::decode(&selected_manifest).unwrap();
    // Key 5 is optional: this is the same valid live body catalog without
    // separately named whole-pack and detached-index container admission.
    manifest.inventory = None;
    tokio::fs::write(&path, manifest.encode().unwrap())
        .await
        .unwrap();

    assert_eq!(bucket.get(&original_id, None).await.unwrap(), raw(original));
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
    assert!(bucket.catalog().await.unwrap().inventory.is_some());

    // The selected manifest cannot lose completeness through an unselected
    // cache edit. Exact administrative repair restores the durable artifact.
    tokio::fs::write(path, selected_manifest).await.unwrap();

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.get(&original_id, None).await.unwrap(),
        raw(original)
    );

    let added = b"new catalog body";
    let added_id = chunk_identity(added);
    reopened
        .put(upload(
            &raw(added),
            &added_id,
            added.len(),
            &reopened.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();

    assert_eq!(
        reopened.get(&original_id, None).await.unwrap(),
        raw(original)
    );
    assert_eq!(
        reopened.has(&[original_id, added_id]).await.unwrap(),
        vec![true, true]
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn manifest_admission_rechecks_nonfinal_context_after_inventory_only_import() {
    use crate::pack::{PackClass, PackId, PackWriter};

    let bucket = fixture().await;
    let profile = &bucket.inner.config.chunk_profile;
    let first = vec![7; profile.minimum() + 1];
    assert!(!profile.valid_nonfinal_chunk(&first));
    let last = b"last";
    let first_id = chunk_identity(&first);
    let last_id = chunk_identity(last);
    for (bytes, identity) in [(first.as_slice(), &first_id), (last.as_slice(), &last_id)] {
        bucket
            .put(upload(
                &raw(bytes),
                identity,
                bytes.len(),
                profile,
                ChunkPosition::Final,
            ))
            .await
            .unwrap();
    }

    let manifest = Manifest {
        size: (first.len() + last.len()) as u64,
        chunks: vec![
            ChunkRef {
                digest: first_id.terrane_v1_digest().unwrap(),
                length: first.len() as u64,
            },
            ChunkRef {
                digest: last_id.terrane_v1_digest().unwrap(),
                length: last.len() as u64,
            },
        ],
        hashes: BTreeMap::from([("blake3".into(), vec![0; 32])]),
        media_type: None,
    };
    let bytes = manifest.encode(profile).unwrap();
    let manifest_id = TERRANE_V1
        .calculate(IdentityKind::Manifest, &bytes)
        .unwrap();
    let mut writer = PackWriter::new(PackId::from_random_bytes([31; 16]), PackClass::Meta, false);
    writer
        .append_raw(crate::pack::EntryKind::Manifest, &bytes)
        .unwrap();
    let sealed = writer.seal().unwrap();
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, sealed.bytes()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        bucket
            .has(std::slice::from_ref(&manifest_id))
            .await
            .unwrap(),
        vec![false]
    );

    let before = bucket.catalog().await.unwrap().capabilities.generation;
    let error = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &bytes).unwrap(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-16" })
    ));
    assert_eq!(
        bucket.catalog().await.unwrap().capabilities.generation,
        before
    );
    assert_eq!(
        bucket.has(&[manifest_id, first_id, last_id]).await.unwrap(),
        vec![false, true, true]
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}
