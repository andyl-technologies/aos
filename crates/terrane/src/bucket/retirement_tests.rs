//! Proves physical retirement fences and exact restore on native durable catalogs.

#![allow(clippy::unwrap_used)]

use super::content_tests::{chunk_identity, fixture, raw, upload};
use super::readmission_tests::publish_members;
use super::tests::{Validator, config};
use super::*;
use crate::store::{
    ChunkPosition, ContentStore, ContentUpload, MetaUpload, TokioClock, TokioLocalFs,
};
use std::collections::BTreeSet;
use terrane_core::bucket::PackExclusion;
use terrane_core::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn physical_retirement_survives_fresh_readmission_and_exact_restore() {
    let bucket = fixture().await;
    assert_eq!(bucket.catalog().await.unwrap().exclusions, Some(Vec::new()));
    let first = b"fresh replacement preserves physical exclusion";
    let other = b"restore eligible old body";
    let bad = b"sticky quarantine survives physical restore";
    let (old, _, _) = publish_members_with_index_alias(&bucket, &[first, other, bad]).await;
    let first_id = chunk_identity(first);
    let other_id = chunk_identity(other);
    let bad_id = chunk_identity(bad);
    bucket.exclude(&bad_id).await.unwrap();
    let before = bucket.catalog().await.unwrap();
    let entry = before
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|entry| entry.pack_id == *old.as_bytes())
        .unwrap();
    let (retained, index) = bucket.verified_container(entry).await.unwrap();
    let pack_id = TERRANE_V1.calculate(IdentityKind::Pack, &retained).unwrap();
    let index_id = TERRANE_V1.calculate(IdentityKind::Index, &index).unwrap();
    // The same detached-index identity may already have an independent metadata
    // placement; its container identity still names the retired physical pack.
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &index).unwrap(),
        ))
        .await
        .unwrap();
    let before = bucket.catalog().await.unwrap();
    let exclusion = PackExclusion {
        pack_id: *old.as_bytes(),
        cycle: 101,
        epoch: 7,
    };

    let guard = bucket.exclusive().await.unwrap();
    bucket
        .retire_pack_locked(
            before,
            exclusion.clone(),
            index_id.terrane_v1_digest().unwrap(),
            &BTreeSet::new(),
        )
        .await
        .unwrap();
    drop(guard);
    // No trash has been created: selected exclusion itself must already fence
    // every content-facing route and remain authoritative across reopen.
    assert_eq!(
        bucket
            .has(&[
                first_id.clone(),
                other_id.clone(),
                bad_id.clone(),
                pack_id.clone(),
                index_id.clone()
            ])
            .await
            .unwrap(),
        vec![false; 5]
    );
    for identity in [&first_id, &pack_id, &index_id] {
        assert!(matches!(
            bucket.get(identity, None).await.unwrap_err().kind(),
            StoreErrorKind::Absent(_)
        ));
        assert!(
            !bucket
                .published_identities(identity.kind())
                .await
                .unwrap()
                .contains(identity)
        );
    }
    assert!(matches!(
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Pack, &retained).unwrap()
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Absent(_)
    ));
    assert!(matches!(
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Index, &index).unwrap()
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Absent(_)
    ));
    bucket
        .put(upload(
            &raw(first),
            &first_id,
            first.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let current = bucket.catalog().await.unwrap();
    assert_eq!(current.exclusions, Some(vec![exclusion.clone()]));
    let fresh = current
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &first_id.terrane_v1_digest().unwrap())
        .unwrap()
        .pack();
    assert_ne!(fresh, old);
    assert_eq!(
        bucket
            .has(&[first_id.clone(), pack_id.clone(), index_id.clone()])
            .await
            .unwrap(),
        vec![true, false, false]
    );

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let guard = reopened.exclusive().await.unwrap();
    let mut stale = exclusion.clone();
    stale.epoch += 1;
    assert!(
        !reopened
            .restore_pack_locked(reopened.catalog().await.unwrap(), &stale)
            .await
            .unwrap()
    );
    assert!(
        reopened
            .restore_pack_locked(reopened.catalog().await.unwrap(), &exclusion)
            .await
            .unwrap()
    );
    drop(guard);
    let selected = reopened.catalog().await.unwrap();
    assert_eq!(selected.exclusions, Some(Vec::new()));
    assert_eq!(
        selected
            .shards
            .iter()
            .flat_map(|shard| shard.entries())
            .find(|entry| entry.entry().hash() == &first_id.terrane_v1_digest().unwrap())
            .unwrap()
            .pack(),
        fresh
    );
    assert_eq!(
        reopened
            .has(&[
                first_id.clone(),
                other_id.clone(),
                bad_id.clone(),
                pack_id,
                index_id
            ])
            .await
            .unwrap(),
        vec![true, true, false, true, true]
    );
    assert_eq!(reopened.get(&first_id, None).await.unwrap(), raw(first));
    assert_eq!(reopened.get(&other_id, None).await.unwrap(), raw(other));
    assert!(matches!(
        reopened
            .put(upload(
                &raw(bad),
                &bad_id,
                bad.len(),
                &reopened.inner.config.chunk_profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn legacy_unknown_retirement_never_loses_its_last_physical_evidence() {
    let bucket = fixture().await;
    let body = b"legacy retirement evidence";
    let identity = chunk_identity(body);
    let (old, _, _) = publish_members_with_index_alias(&bucket, &[body]).await;
    let initial = bucket.catalog().await.unwrap();
    let old_entry = initial
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|entry| entry.pack_id == *old.as_bytes())
        .unwrap();
    let index_hash = old_entry.index_hash;
    let index = bucket.verified_container(old_entry).await.unwrap().1;
    let index_identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &index).unwrap(),
        ))
        .await
        .unwrap();
    let guard = bucket.exclusive().await.unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let exclusion = PackExclusion {
        pack_id: *old.as_bytes(),
        cycle: 3,
        epoch: 1,
    };
    let mut marked = BTreeSet::new();
    marked.insert(identity.terrane_v1_digest().unwrap());
    assert!(matches!(
        bucket
            .retire_pack_locked(
                bucket.catalog().await.unwrap(),
                exclusion.clone(),
                index_hash,
                &marked
            )
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    bucket
        .retire_pack_locked(catalog, exclusion, index_hash, &BTreeSet::new())
        .await
        .unwrap();
    let mut incomplete = bucket.catalog().await.unwrap();
    incomplete.inventory = None;
    let generation = bucket.next_generation(&incomplete).await.unwrap();
    let shards = incomplete
        .shards
        .iter()
        .map(|shard| {
            crate::pack::MergedShard::decode(&shard.encode(), generation, shard.shard()).unwrap()
        })
        .collect::<Vec<_>>();
    bucket
        .publish_shards(incomplete, generation, &shards)
        .await
        .unwrap();
    let selected = bucket.catalog().await.unwrap();
    assert!(selected.exclusions.is_some());
    assert!(matches!(
        bucket
            .verified_body(&selected, &index_identity)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    let mut legacy = selected;
    legacy.exclusions = None;
    legacy.inventory = None;
    let generation = bucket.next_generation(&legacy).await.unwrap();
    let shards = legacy
        .shards
        .iter()
        .map(|shard| {
            crate::pack::MergedShard::decode(&shard.encode(), generation, shard.shard()).unwrap()
        })
        .collect::<Vec<_>>();
    bucket
        .publish_shards(legacy, generation, &shards)
        .await
        .unwrap();
    drop(guard);
    assert!(matches!(
        bucket
            .put(upload(
                &raw(body),
                &identity,
                body.len(),
                &bucket.inner.config.chunk_profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket.exclude(&identity).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket.get(&index_identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .has(std::slice::from_ref(&index_identity))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .published_identities(IdentityKind::Index)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Index, &index).unwrap()
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(bucket.catalog().await.unwrap().exclusions, None);
    assert_eq!(bucket.has(&[identity]).await.unwrap(), vec![false]);
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.catalog().await.unwrap().exclusions, None);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn physical_exclusion_overrides_live_rows_during_fresh_admission() {
    let bucket = fixture().await;
    let body = b"live row cannot acknowledge a physically retired placement";
    let other = b"another old member remains physically excluded";
    let identity = chunk_identity(body);
    let other_identity = chunk_identity(other);
    let old = publish_members(&bucket, &[body, other]).await;
    let guard = bucket.exclusive().await.unwrap();
    let mut catalog = bucket.catalog().await.unwrap();
    let exclusion = PackExclusion {
        pack_id: *old.as_bytes(),
        cycle: 201,
        epoch: 9,
    };
    // Physical authority must fence even a selected legacy or mixed-state row
    // that still says Live. Fresh admission cannot preserve that unavailable row.
    catalog.exclusions = Some(vec![exclusion.clone()]);
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let shards = catalog
        .shards
        .iter()
        .map(|shard| {
            crate::pack::MergedShard::decode(&shard.encode(), generation, shard.shard()).unwrap()
        })
        .collect::<Vec<_>>();
    bucket
        .publish_shards(catalog, generation, &shards)
        .await
        .unwrap();
    drop(guard);
    assert_eq!(
        bucket
            .has(&[identity.clone(), other_identity.clone()])
            .await
            .unwrap(),
        vec![false, false]
    );

    bucket
        .put(upload(
            &raw(body),
            &identity,
            body.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    assert_eq!(bucket.get(&identity, None).await.unwrap(), raw(body));
    let selected = bucket.catalog().await.unwrap();
    assert_eq!(selected.exclusions, Some(vec![exclusion.clone()]));
    let placement = selected
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_ne!(placement.pack(), old);
    assert_eq!(placement.state(), crate::pack::RecordState::Live);
    assert_eq!(
        bucket
            .has(&[identity.clone(), other_identity.clone()])
            .await
            .unwrap(),
        vec![true, false]
    );

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.get(&identity, None).await.unwrap(), raw(body));
    assert_eq!(
        reopened.catalog().await.unwrap().exclusions,
        Some(vec![exclusion])
    );
    assert_eq!(reopened.has(&[other_identity]).await.unwrap(), vec![false]);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn legacy_state1_without_inventory_blocks_opaque_index_aliases_even_with_empty_key6() {
    let bucket = fixture().await;
    let body = b"legacy state1 physical evidence outside key6";
    let (old, _, _) = publish_members_with_index_alias(&bucket, &[body]).await;
    let initial = bucket.catalog().await.unwrap();
    let row = initial
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| row.pack_id == *old.as_bytes())
        .unwrap();
    let index = bucket.verified_container(row).await.unwrap().1;
    let identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &index).unwrap(),
        ))
        .await
        .unwrap();
    let guard = bucket.exclusive().await.unwrap();
    let mut catalog = bucket.catalog().await.unwrap();
    catalog
        .inventory
        .as_mut()
        .unwrap()
        .retain(|row| row.pack_id != *old.as_bytes());
    assert_eq!(catalog.exclusions, Some(Vec::new()));
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let shards = catalog
        .shards
        .iter()
        .map(|shard| {
            let mut rows =
                terrane_core::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap();
            for row in &mut rows {
                if row.pack == *old.as_bytes() {
                    row.state = crate::pack::RecordState::Tombstone as u8;
                }
            }
            crate::pack::MergedShard::decode(
                &terrane_core::pack_format::encode_shard(&rows),
                generation,
                shard.shard(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    bucket
        .publish_shards(catalog, generation, &shards)
        .await
        .unwrap();
    drop(guard);

    assert!(matches!(
        bucket.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .published_identities(IdentityKind::Index)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Index, &index).unwrap()
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    let before = bucket.catalog().await.unwrap().capabilities.generation;
    let body_identity = chunk_identity(body);
    assert!(matches!(
        bucket.exclude(&body_identity).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        bucket
            .put(upload(
                &raw(body),
                &body_identity,
                body.len(),
                &bucket.inner.config.chunk_profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
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
    assert!(matches!(
        reopened.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(
        reopened.catalog().await.unwrap().exclusions,
        Some(Vec::new())
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

/// Admits an independent index body before publishing its named physical pack.
async fn publish_members_with_index_alias(
    bucket: &FileBucket<TokioLocalFs, TokioClock, Validator>,
    members: &[&[u8]],
) -> (
    crate::pack::PackId,
    terrane_core::identity::Identity,
    Vec<u8>,
) {
    use crate::pack::{EntryKind, PackClass, PackId, PackIndexSnapshot, PackWriter};
    let id = PackId::generate(&bucket.inner.fs).await.unwrap();
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    for member in members {
        writer.append_raw(EntryKind::Chunk, member).unwrap();
    }
    let sealed = writer.seal().unwrap();
    let index_bytes = sealed.index_object().to_vec();
    let identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &index_bytes).unwrap(),
        ))
        .await
        .unwrap();
    let guard = bucket.exclusive().await.unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let independent = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_ne!(independent.pack(), id);
    assert_eq!(independent.entry().kind(), EntryKind::Index);
    bucket
        .immutable(&BucketKey::parse(&id.pack_key()).unwrap(), sealed.bytes())
        .await
        .unwrap();
    bucket
        .immutable(&BucketKey::parse(&id.index_key()).unwrap(), &index_bytes)
        .await
        .unwrap();
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let index = PackIndexSnapshot::decode(&index_bytes, generation).unwrap();
    let inventory = super::containers::inventory_entry(id, sealed.bytes(), &index_bytes).unwrap();
    bucket
        .publish_pack_catalog(catalog, index, inventory)
        .await
        .unwrap();
    drop(guard);
    (id, identity, index_bytes)
}
