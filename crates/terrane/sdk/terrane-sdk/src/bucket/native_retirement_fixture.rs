//! Supplies actual native collection authority for bucket retirement witnesses.
//!
//! Rich content assertions use genuine current roots, a whole collector lease,
//! backend age and actual retained pack/index descriptors; raw records grant none.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native assertions intentionally panic."
)]

/// Checks stale nominal Live rows under actual retained native exclusion.
pub(super) mod stale_live;

use super::content_tests::{chunk_identity, raw, upload};
use super::*;
use crate::gc::runner::{Collection, fixture::Fixture};
use crate::pack::{EntryKind, PackClass, PackId, PackIndexSnapshot, PackWriter, RecordState};
use crate::store::{
    ChunkPosition, Clock, ContentStore, ContentUpload, IndexedContent, MetaUpload, TokioClock,
};
use terrane_format::bucket::PackExclusion;
use terrane_format::gc::{Tombstone, Windows};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Checks fresh reupload after genuine native retirement without restoring its old pack.
///
/// # Panics
/// Panics when actual qualification or an independent content assertion fails.
pub(super) async fn verified_reupload_replaces_gc_retired_placement_without_restoring_old_pack() {
    let fixture = Fixture::new().await;
    let bucket = fixture.guard().store().clone();
    let plaintext = b"freshly verified content after collection";
    let identity = chunk_identity(plaintext);
    let encoded = raw(plaintext);
    let profile = &fixture.config.chunk_profile;
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

    let old = bucket
        .catalog()
        .await
        .unwrap()
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &hash)
        .unwrap()
        .pack();
    let (collection, tombstone) = retire(&fixture, old).await;
    let trash = BucketKey::parse(&format!("trash/{}/{old}", tombstone.cycle)).unwrap();
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
        fixture.config.clone(),
        fixture.fs.clone(),
        fixture.clock.retain_native_clock().unwrap(),
        crate::gc::runner::fixture::Validator,
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
    drop(reopened);
    drop(collection);
    drop(bucket);
    fixture.cleanup();
}

/// Checks exact native restore while preserving fresh placement and sticky quarantine.
///
/// # Panics
/// Panics when actual qualification or an independent content assertion fails.
pub(super) async fn physical_retirement_survives_fresh_readmission_and_exact_restore() {
    let fixture = Fixture::new().await;
    let bucket = fixture.guard().store().clone();
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
    let (mut collection, trash) = retire(&fixture, old).await;
    let exclusion = PackExclusion {
        pack_id: trash.pack,
        cycle: trash.cycle,
        epoch: trash.epoch,
    };
    assert_eq!(
        bucket
            .read_optional(&BucketKey::parse(&format!("trash/{}/{old}", trash.cycle)).unwrap())
            .await
            .unwrap(),
        Some(trash.encode())
    );
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
    assert_eq!(
        bucket
            .indexed_presence(&[
                first_id.terrane_v1_digest().unwrap(),
                other_id.terrane_v1_digest().unwrap(),
                bad_id.terrane_v1_digest().unwrap(),
            ])
            .await
            .unwrap(),
        vec![false; 3]
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
    let pack_error = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, &retained).unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(
        pack_error.kind(),
        &StoreErrorKind::Absent(pack_id.clone()),
        "retired pack admission returned {pack_error:?}",
    );
    let index_error = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &index).unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(
        index_error.kind(),
        &StoreErrorKind::Absent(index_id.clone()),
        "retired detached-index admission returned {index_error:?}",
    );
    bucket
        .put(upload(
            &raw(first),
            &first_id,
            first.len(),
            &fixture.config.chunk_profile,
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
        fixture.config.clone(),
        fixture.fs.clone(),
        fixture.clock.retain_native_clock().unwrap(),
        crate::gc::runner::fixture::Validator,
    )
    .await
    .unwrap();
    let mut stale = exclusion.clone();
    stale.epoch += 1;
    assert!(!collection.restore_pack(stale).await.unwrap());
    assert!(collection.restore_pack(exclusion.clone()).await.unwrap());
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
    assert_eq!(
        reopened
            .indexed_presence(&[
                first_id.terrane_v1_digest().unwrap(),
                other_id.terrane_v1_digest().unwrap(),
                bad_id.terrane_v1_digest().unwrap(),
            ])
            .await
            .unwrap(),
        vec![true, true, false]
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
    drop(reopened);
    drop(collection);
    drop(bucket);
    fixture.cleanup();
}

/// Names the existing genuine native collector fixture bindings.
type NativeCollection<'a> = Collection<
    'a,
    crate::store::native_publication_effects::collection::test_fs::TestFs,
    crate::store::NativeEffectClock,
    crate::gc::runner::fixture::Validator,
    crate::store::NativeEffectClock,
>;

/// Completes actual current marking, then retires the selected aged native pair.
async fn retire<'a>(fixture: &'a Fixture, expected: PackId) -> (NativeCollection<'a>, Tombstone) {
    let modified = rounded_modified(&fixture.config.root.join(expected.pack_key())).max(
        rounded_modified(&fixture.config.root.join(expected.index_key())),
    );
    let windows = Windows::new(30, 60, 60, 90).unwrap();
    let base = modified
        .checked_add(windows.grace())
        .unwrap()
        .checked_add(1)
        .unwrap();
    fixture.clock.set(base, base.checked_sub(100).unwrap());
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "bucket-retirement".into(),
        1_000,
        101,
        windows,
    )
    .await
    .unwrap();
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    let trash = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trash.pack, *expected.as_bytes());
    (collection, trash)
}

fn rounded_modified(path: &std::path::Path) -> u64 {
    let elapsed = std::fs::symlink_metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    elapsed
        .as_secs()
        .checked_add(u64::from(elapsed.subsec_nanos() != 0))
        .unwrap()
}

/// Stages the real data pair before admitting its independent index metadata body.
///
/// Actual later metadata age keeps that separate unrooted pack outside G while
/// the data pair first qualifies. Neither clock policy nor filesystem age changes.
async fn publish_members_with_index_alias(
    bucket: &crate::gc::runner::fixture::Bucket,
    members: &[&[u8]],
) -> (PackId, terrane_format::identity::Identity, Vec<u8>) {
    let id = PackId::generate(&bucket.inner.fs).await.unwrap();
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    for member in members {
        writer.append_raw(EntryKind::Chunk, member).unwrap();
    }
    let sealed = writer.seal().unwrap();
    let index_bytes = sealed.index_object().to_vec();
    {
        let holder = super::held::SingleHeld::acquire(bucket).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication().await.unwrap();
        let artifacts =
            super::containers::admitted_artifacts(id, sealed.bytes(), &index_bytes).unwrap();
        crate::store::native_publication_effects::stage_container(
            &bucket.inner.fs,
            &observed,
            &artifacts,
        )
        .await
        .unwrap();
    }
    let upper = rounded_modified(&bucket.root().join(id.pack_key()))
        .max(rounded_modified(&bucket.root().join(id.index_key())));
    let mut later = false;
    for _ in 0..300 {
        if TokioClock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            > upper
        {
            later = true;
            break;
        }
        TokioClock
            .sleep(std::time::Duration::from_millis(10))
            .await
            .unwrap();
    }
    assert!(
        later,
        "actual metadata admission must be newer than the staged data pair"
    );
    let identity = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, &index_bytes).unwrap(),
        ))
        .await
        .unwrap();
    let holder = super::held::SingleHeld::acquire(bucket).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication().await.unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let independent = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_ne!(independent.pack(), id);
    assert_eq!(independent.entry().kind(), EntryKind::Index);
    assert!(rounded_modified(&bucket.root().join(independent.pack().pack_key())) > upper);
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let index = PackIndexSnapshot::decode(&index_bytes, generation).unwrap();
    let inventory = super::containers::inventory_entry(id, sealed.bytes(), &index_bytes).unwrap();
    bucket
        .publish_pack_catalog(&held, &observed, catalog, index, inventory)
        .await
        .unwrap();
    (id, identity, index_bytes)
}
