//! Checks copied-burn format data without minting copy or maintenance authority.
//!
//! Actual selected copy/permanent-owner qualification requires their genuine
//! producers. These witnesses exercise canonical data policy against real
//! admitted artifacts and preserve supported fresh read/admission paths.

use super::*;
use crate::bucket::content_tests::{chunk_identity, raw, upload};
use crate::pack::{EntryKind, PackClass, PackId, PackWriter};
use crate::store::{ChunkPosition, ContentStore, ContentUpload, MetaUpload};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};

async fn admit(bucket: &FileBucket<ReadFs, TokioClock, Validator>, body: &[u8]) -> Identity {
    let encoded = raw(body);
    let identity = chunk_identity(body);
    let profile = terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]);
    bucket
        .put(upload(
            &encoded,
            &identity,
            body.len(),
            &profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn represented_burn_without_old_artifacts_keeps_fresh_reads_and_denies_detached_alias() {
    let (parent, bucket) = fixture().await;
    let old_id = PackId::generate(&bucket.inner.fs).await.unwrap();
    let mut writer = PackWriter::new(old_id, PackClass::Data, false);
    writer
        .append_raw(EntryKind::Chunk, b"unadmitted old container member")
        .unwrap();
    let sealed = writer.seal().unwrap();
    let old_index = sealed.index_object().to_vec();
    // Admit the detached index as a member before its named container exists,
    // so the alias is genuinely stored in a separate live carrier.
    let alias = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &old_index).unwrap(),
        ))
        .await
        .unwrap();
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, sealed.bytes()).unwrap(),
        ))
        .await
        .unwrap();
    let admitted = bucket.catalog().await.unwrap();
    let carrier = admitted
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == alias.digest())
        .unwrap()
        .pack();
    assert_ne!(carrier, old_id);
    assert_eq!(bucket.get(&alias, None).await.unwrap(), old_index);
    let fresh_body = b"eligible fresh placement";
    let fresh = admit(&bucket, fresh_body).await;
    let mut data = bucket.catalog().await.unwrap();
    let fresh_id = data
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == fresh.digest())
        .unwrap()
        .pack();
    let fresh_entry = data
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|entry| entry.pack_id == *fresh_id.as_bytes())
        .unwrap();
    let fresh_index_identity = TERRANE_V1
        .from_digest(IdentityKind::Index, &fresh_entry.index_hash)
        .unwrap();
    let fresh_index = TokioLocalFs
        .read_nofollow(&bucket.root().join(fresh_id.index_key()))
        .await
        .unwrap();
    assert_eq!(
        bucket.get(&fresh_index_identity, None).await.unwrap(),
        fresh_index
    );
    assert_eq!(
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Index, &fresh_index).unwrap()
            ))
            .await
            .unwrap(),
        fresh_index_identity
    );

    // Unselected data represents a copied burn whose source artifacts/inventory
    // are unavailable. It does not install a burn, owner or collector lease.
    data = bucket.catalog().await.unwrap();
    data.burns = Some(vec![*old_id.as_bytes()]);
    data.inventory
        .as_mut()
        .unwrap()
        .retain(|entry| entry.pack_id != *old_id.as_bytes());
    tokio::fs::remove_file(bucket.root().join(old_id.pack_key()))
        .await
        .unwrap();
    tokio::fs::remove_file(bucket.root().join(old_id.index_key()))
        .await
        .unwrap();
    assert!(bucket.index_retirement_known(&data));
    assert!(bucket.detached_index_excluded(&data, &old_index).unwrap());
    assert_eq!(
        bucket.verified_body(&data, &fresh).await.unwrap(),
        raw(fresh_body)
    );
    assert_eq!(
        bucket
            .verified_body(&data, &fresh_index_identity)
            .await
            .unwrap(),
        fresh_index
    );
    assert!(matches!(
        bucket
            .verified_body(&data, &alias)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Absent(_)
    ));

    let candidates = bucket
        .catalog_identities(&data, IdentityKind::Index)
        .unwrap();
    let eligible = bucket
        .verified_catalog_identities(&data, candidates)
        .await
        .unwrap();
    assert!(!eligible.contains(&alias));
    assert!(eligible.contains(&fresh_index_identity));
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn index_policy_keeps_unknown_burn_completeness_distinct_from_known_empty() {
    let (parent, bucket) = fixture().await;
    let member = admit(&bucket, b"known empty is represented").await;
    let mut data = bucket.catalog().await.unwrap();
    assert_eq!(data.burns, Some(Vec::new()));
    assert!(bucket.index_retirement_known(&data));
    let row = data.inventory.as_ref().unwrap().first().unwrap();
    let id = PackId::from_random_bytes(row.pack_id);
    let bytes = TokioLocalFs
        .read_nofollow(&bucket.root().join(id.index_key()))
        .await
        .unwrap();
    let index = TERRANE_V1
        .from_digest(IdentityKind::Index, &row.index_hash)
        .unwrap();
    assert!(!bucket.detached_index_excluded(&data, &bytes).unwrap());

    data.burns = None;
    assert!(!bucket.index_retirement_known(&data));
    assert!(matches!(
        bucket
            .verified_body(&data, &index)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(
        bucket.verified_body(&data, &member).await.unwrap(),
        raw(b"known empty is represented")
    );
    data.burns = Some(Vec::new());
    data.exclusions = None;
    assert!(!bucket.index_retirement_known(&data));
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn detached_index_policy_checks_canonical_header_and_preserves_other_index_formats() {
    let (parent, bucket) = fixture().await;
    let data = bucket.catalog().await.unwrap();
    assert!(
        !bucket
            .detached_index_excluded(&data, b"opaque generic index")
            .unwrap()
    );
    assert!(bucket.detached_index_excluded(&data, b"TRPK").is_err());
    let merged = data.shards.first().unwrap().encode();
    assert!(!bucket.detached_index_excluded(&data, &merged).unwrap());

    let identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &merged).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(bucket.get(&identity, None).await.unwrap(), merged);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn index_alias_filter_preserves_missing_bodies_and_original_error_priority() {
    let (parent, bucket) = fixture().await;
    let member = admit(&bucket, b"a missing body remains a listing failure").await;
    let data = bucket.catalog().await.unwrap();
    let id = data
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == member.digest())
        .unwrap()
        .pack();
    let pack = bucket.root().join(id.pack_key());
    let original = TokioLocalFs.read_nofollow(&pack).await.unwrap();
    let missing_chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"not an admitted member")
        .unwrap();
    let missing_index = TERRANE_V1
        .calculate(IdentityKind::Index, b"not an admitted index")
        .unwrap();

    // Absence cannot stand in for a verified embedded pack association, even
    // for an Index candidate. Keep the first candidate's exact error.
    for missing in [missing_chunk, missing_index] {
        bucket.inner.fs.reset_read_counters();
        assert_eq!(
            bucket
                .verified_catalog_identities(&data, vec![missing.clone(), member.clone()])
                .await
                .unwrap_err()
                .kind(),
            &StoreErrorKind::Absent(missing.clone())
        );
        assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    }

    *bucket.inner.fs.read_failure.lock().unwrap() = Some(pack.clone());
    assert!(matches!(
        bucket
            .verified_catalog_identities(
                &data,
                vec![
                    member.clone(),
                    TERRANE_V1
                        .calculate(IdentityKind::Chunk, b"later missing")
                        .unwrap()
                ]
            )
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    bucket.inner.fs.read_failure.lock().unwrap().take();

    tokio::fs::remove_file(&pack).await.unwrap();
    assert!(matches!(
        bucket
            .live_identities(IdentityKind::Chunk)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert!(matches!(
        bucket
            .published_identities(IdentityKind::Index)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    tokio::fs::write(&pack, &original).await.unwrap();
    let mut damaged = original;
    *damaged.last_mut().unwrap() ^= 1;
    tokio::fs::write(&pack, &damaged).await.unwrap();
    assert!(matches!(
        bucket
            .verified_catalog_identities(&data, vec![member])
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.retained_effects.load(Ordering::SeqCst), 0);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}
