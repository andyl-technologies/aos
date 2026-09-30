//! Exercises independent container admission and durable per-identity exclusion.

#![allow(clippy::unwrap_used)]

use super::content_tests::{chunk_identity, fixture, raw, upload};
use super::tests::{Validator, config};
use super::*;
use crate::store::{
    ChunkPosition, ContentStore, ContentUpload, MetaUpload, TokioClock, TokioLocalFs,
};
use terrane_core::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn container_inventory_cannot_resurrect_an_excluded_index_identity() {
    use crate::pack::{EntryKind, PackClass, PackId, PackWriter};

    let bucket = fixture().await;
    let mut writer = PackWriter::new(PackId::from_random_bytes([37; 16]), PackClass::Data, false);
    writer
        .append_raw(EntryKind::Chunk, b"unadmitted member")
        .unwrap();
    let sealed = writer.seal().unwrap();
    let index_upload = MetaUpload::new(IdentityKind::Index, sealed.index_object()).unwrap();
    let index_identity = bucket.put(ContentUpload::Meta(index_upload)).await.unwrap();
    let pack_upload = MetaUpload::new(IdentityKind::Pack, sealed.bytes()).unwrap();
    let pack_identity = bucket.put(ContentUpload::Meta(pack_upload)).await.unwrap();
    assert_eq!(
        bucket.get(&index_identity, None).await.unwrap(),
        sealed.index_object()
    );

    bucket.exclude(&index_identity).await.unwrap();
    assert_eq!(
        bucket
            .has(&[index_identity.clone(), pack_identity.clone()])
            .await
            .unwrap(),
        vec![false, true]
    );
    assert!(
        !bucket
            .published_identities(IdentityKind::Index)
            .await
            .unwrap()
            .contains(&index_identity)
    );
    assert!(matches!(
        bucket
            .put(ContentUpload::Meta(index_upload))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(
        bucket.put(ContentUpload::Meta(pack_upload)).await.unwrap(),
        pack_identity
    );

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .has(&[index_identity, pack_identity])
            .await
            .unwrap(),
        vec![false, true]
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn whole_pack_import_verifies_members_without_admitting_them() {
    use crate::pack::{EntryKind, PackClass, PackId, PackWriter};

    let bucket = fixture().await;
    let mut writer = PackWriter::new(
        PackId::generate(&TokioLocalFs).await.unwrap(),
        PackClass::Data,
        false,
    );
    let plaintext = b"verified imported member";
    writer.append_raw(EntryKind::Chunk, plaintext).unwrap();
    let pack = writer.seal().unwrap();
    let expected = TERRANE_V1
        .calculate(IdentityKind::Pack, pack.bytes())
        .unwrap();
    let index = TERRANE_V1
        .calculate(IdentityKind::Index, pack.index_object())
        .unwrap();

    let identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, pack.bytes()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(identity, expected);
    assert_eq!(bucket.get(&identity, None).await.unwrap(), pack.bytes());
    assert_eq!(bucket.get(&index, None).await.unwrap(), pack.index_object());
    assert_eq!(
        bucket
            .has(&[identity.clone(), index.clone(), chunk_identity(plaintext)])
            .await
            .unwrap(),
        vec![true, true, false]
    );
    let before = bucket.catalog().await.unwrap().capabilities.generation;
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, pack.bytes()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        bucket.catalog().await.unwrap().capabilities.generation,
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
    assert_eq!(
        reopened
            .has(&[identity, index, chunk_identity(plaintext)])
            .await
            .unwrap(),
        vec![true, true, false]
    );
    let mut bad = pack.bytes().to_vec();
    bad[crate::pack::HEADER_SIZE + 1] ^= 1;
    assert!(
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Pack, &bad).unwrap()
            ))
            .await
            .is_err()
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn quarantine_survives_reopen_and_container_or_body_republication() {
    let bucket = fixture().await;
    let plaintext = b"quarantined immutable body";
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
    let inventory = bucket.catalog().await.unwrap().inventory.unwrap();
    let retained = bucket.verified_container(&inventory[0]).await.unwrap().0;

    bucket.exclude(&identity).await.unwrap();
    bucket.exclude(&identity).await.unwrap();
    assert_eq!(
        bucket.has(std::slice::from_ref(&identity)).await.unwrap(),
        vec![false]
    );
    assert!(matches!(
        bucket
            .put(upload(
                &encoded,
                &identity,
                plaintext.len(),
                &bucket.inner.config.chunk_profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, &retained).unwrap(),
        ))
        .await
        .unwrap();
    let other = b"independent live body";
    let other_id = chunk_identity(other);
    bucket
        .put(upload(
            &raw(other),
            &other_id,
            other.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
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
    assert_eq!(
        reopened.has(&[identity, other_id]).await.unwrap(),
        vec![false, true]
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}
