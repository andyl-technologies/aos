//! Exercises fresh verified admission after a GC placement is retired.

#![allow(clippy::unwrap_used)]

use super::content_tests::{chunk_identity, fixture, raw, upload};
use super::tests::{Validator, config};
use super::*;
use crate::pack::{
    EntryKind, MergedShard, PackClass, PackId, PackIndexSnapshot, PackWriter, RecordState,
};
use crate::store::{ChunkPosition, ContentStore, TokioClock, TokioLocalFs};
use terrane_core::bucket::{PackExclusion, Tombstone};

#[tokio::test]
async fn verified_reupload_replaces_gc_retired_placement_without_restoring_old_pack() {
    let bucket = fixture().await;
    let plaintext = b"freshly verified content after collection";
    let identity = chunk_identity(plaintext);
    let encoded = raw(plaintext);
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
    let hash = identity.terrane_v1_digest().unwrap();

    // Author the exact persisted GC effect under backend exclusion. Collector
    // lease/orchestration tests belong to GC; this exercises bucket admission
    // against real selected shards and the durable retained-pack tombstone.
    let guard = bucket.exclusive().await.unwrap();
    let mut catalog = bucket.catalog().await.unwrap();
    let old = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &hash)
        .unwrap()
        .pack();
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let tombstone = Tombstone {
        pack_id: *old.as_bytes(),
        cycle: 42,
        tombstoned_at: 1,
        removed_entries: 1,
        epoch: 1,
    };
    let trash = BucketKey::parse(&format!("trash/42/{old}")).unwrap();
    bucket
        .install(&trash, &tombstone.encode(), false)
        .await
        .unwrap();
    let mut shards = Vec::new();
    for shard in &catalog.shards {
        let mut records =
            terrane_core::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap();
        for record in &mut records {
            if record.record.hash == hash {
                record.state = RecordState::Tombstone as u8;
            }
        }
        shards.push(
            MergedShard::decode(
                &terrane_core::pack_format::encode_shard(&records),
                generation,
                shard.shard(),
            )
            .unwrap(),
        );
    }
    catalog.exclusions = Some(vec![PackExclusion {
        pack_id: *old.as_bytes(),
        cycle: 42,
        epoch: 1,
    }]);
    bucket
        .publish_shards(catalog, generation, &shards)
        .await
        .unwrap();
    drop(guard);
    assert_eq!(
        bucket.has(std::slice::from_ref(&identity)).await.unwrap(),
        vec![false]
    );

    let old_path = BucketKey::parse(&format!(
        "objects/pack/{}/{old}.pack",
        &old.to_string()[..2]
    ))
    .unwrap();
    let retained_bytes = bucket.read_optional(&old_path).await.unwrap().unwrap();
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
    assert_eq!(bucket.get(&identity, None).await.unwrap(), encoded);
    let current = bucket.catalog().await.unwrap();
    let replacement = current
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &hash)
        .unwrap();
    assert_eq!(replacement.state(), RecordState::Live);
    assert_ne!(replacement.pack(), old);
    assert_eq!(
        bucket.read_optional(&old_path).await.unwrap().unwrap(),
        retained_bytes
    );
    assert_eq!(
        bucket.read_optional(&trash).await.unwrap().unwrap(),
        tombstone.encode()
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
        reopened.read_optional(&trash).await.unwrap().unwrap(),
        tombstone.encode()
    );
    let selected = reopened.catalog().await.unwrap();
    assert_eq!(
        selected
            .shards
            .iter()
            .flat_map(|shard| shard.entries())
            .find(|entry| entry.entry().hash() == &hash)
            .unwrap()
            .pack(),
        replacement.pack()
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

/// Publishes actual verified multi-member pack artifacts through the backend catalog.
pub(super) async fn publish_members(
    bucket: &FileBucket<TokioLocalFs, TokioClock, Validator>,
    members: &[&[u8]],
) -> PackId {
    let guard = super::held::SingleHeld::acquire(bucket).await.unwrap();
    let held = guard.destination();
    let observed = held.observe_publication().await.unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let id = PackId::generate(&bucket.inner.fs).await.unwrap();
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    for member in members {
        writer.append_raw(EntryKind::Chunk, member).unwrap();
    }
    let sealed = writer.seal().unwrap();
    let artifacts =
        super::containers::admitted_artifacts(id, sealed.bytes(), sealed.index_object()).unwrap();
    crate::store::native_publication_effects::stage_container(
        &bucket.inner.fs,
        &observed,
        &artifacts,
    )
    .await
    .unwrap();
    let index = PackIndexSnapshot::decode(sealed.index_object(), 1).unwrap();
    let inventory =
        super::containers::inventory_entry(id, sealed.bytes(), sealed.index_object()).unwrap();
    bucket.verified_container(&inventory).await.unwrap();
    bucket
        .publish_pack_catalog(&held, &observed, catalog, index, inventory)
        .await
        .unwrap();
    drop(observed);
    drop(guard);
    id
}
