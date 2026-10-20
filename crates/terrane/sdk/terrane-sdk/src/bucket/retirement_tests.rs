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
use terrane_format::bucket::PackExclusion;
use terrane_format::identity::IdentityKind;
#[cfg(not(unix))]
use terrane_format::identity::TERRANE_V1;

#[cfg(unix)]
#[tokio::test]
async fn physical_exclusion_overrides_live_rows_during_fresh_admission() {
    super::native_retirement_fixture::stale_live::physical_exclusion_overrides_live_rows_during_fresh_admission().await;
}

#[tokio::test]
async fn physical_retirement_survives_fresh_readmission_and_exact_restore() {
    #[cfg(unix)]
    super::native_retirement_fixture::physical_retirement_survives_fresh_readmission_and_exact_restore().await;

    #[cfg(not(unix))]
    {
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
    let selected_before = bucket.selected_publication_locked().await.unwrap();
    let retained_pack = bucket
        .read_optional(&BucketKey::parse(&old.pack_key()).unwrap())
        .await
        .unwrap();
    let retained_index = bucket
        .read_optional(&BucketKey::parse(&old.index_key()).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        bucket
            .retire_pack_locked(catalog, exclusion, index_hash, &BTreeSet::new())
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    let selected_after = bucket.selected_publication_locked().await.unwrap();
    assert_eq!(selected_after.state, selected_before.state);
    assert_eq!(selected_after.logical, selected_before.logical);
    assert_eq!(
        bucket
            .read_optional(&BucketKey::parse(&old.pack_key()).unwrap())
            .await
            .unwrap(),
        retained_pack
    );
    assert_eq!(
        bucket
            .read_optional(&BucketKey::parse(&old.index_key()).unwrap())
            .await
            .unwrap(),
        retained_index
    );
    // Incomplete ordinary catalog data cannot replace current selected authority.
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
    let authority_before = bucket.selected_publication_locked().await.unwrap();
    assert!(matches!(
        bucket
            .publish_shards(incomplete, generation, &shards)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    let selected = bucket.catalog().await.unwrap();
    assert!(selected.inventory.is_some() && selected.exclusions.is_some());
    let authority_after = bucket.selected_publication_locked().await.unwrap();
    assert_eq!(authority_after.state, authority_before.state);
    assert_eq!(authority_after.digest, authority_before.digest);
    assert_eq!(authority_after.logical, authority_before.logical);

    // Direct lookup treats absent legacy associations as unknown ordinary data.
    // It never installs this edited Catalog as selected authority.
    let mut legacy = selected;
    legacy.inventory = None;
    legacy.exclusions = None;
    assert!(!bucket.is_excluded(&legacy, &index_identity).unwrap());
    assert!(matches!(
        bucket
            .verified_body(&legacy, &index_identity)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));

    drop(guard);
    assert_eq!(bucket.has(&[identity]).await.unwrap(), vec![true]);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn raw_publication_refuses_mixed_live_row_exclusion_without_changing_selected_catalog() {
    let bucket = fixture().await;
    let body = b"raw exclusion proposal preserves the live row";
    let other = b"other live member survives the refused proposal";
    let identity = chunk_identity(body);
    let other_identity = chunk_identity(other);
    let old = publish_members(&bucket, &[body, other]).await;
    let guard = bucket.exclusive().await.unwrap();
    let before = bucket.selected_publication_locked().await.unwrap();
    let mut catalog = bucket.catalog().await.unwrap();
    let exclusion = PackExclusion {
        pack_id: *old.as_bytes(),
        cycle: 201,
        epoch: 9,
    };
    // A proposed mixed live-row exclusion cannot gain collector authority
    // through the raw selected-publication path.
    catalog.exclusions = Some(vec![exclusion.clone()]);
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let shards = catalog
        .shards
        .iter()
        .map(|shard| {
            crate::pack::MergedShard::decode(&shard.encode(), generation, shard.shard()).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        bucket
            .publish_shards(catalog, generation, &shards)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    let after = bucket.selected_publication_locked().await.unwrap();
    assert_eq!(after.state, before.state);
    assert_eq!(after.logical, before.logical);
    drop(guard);
    assert_eq!(
        bucket.has(&[identity, other_identity]).await.unwrap(),
        vec![true, true]
    );
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
    // A missing inventory association alone leaves represented empty sets
    // known while no selected legacy tombstone supplies contrary evidence.
    assert!(bucket.index_retirement_known(&catalog));
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let shards = catalog
        .shards
        .iter()
        .map(|shard| {
            let mut rows =
                terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap();
            for row in &mut rows {
                if row.pack == *old.as_bytes() {
                    row.state = crate::pack::RecordState::Tombstone as u8;
                }
            }
            crate::pack::MergedShard::decode(
                &terrane_format::pack_format::encode_shard(&rows),
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

    let mut evidence = bucket.catalog().await.unwrap();
    assert!(!bucket.index_retirement_known(&evidence));
    assert!(bucket.detached_index_excluded(&evidence, &index).unwrap());

    // These unselected ordinary controls do not install an exclusion or burn.
    // Exact represented physical sets are sufficient even without inventory.
    evidence.exclusions = Some(vec![PackExclusion {
        pack_id: *old.as_bytes(),
        cycle: 301,
        epoch: 1,
    }]);
    assert!(bucket.index_retirement_known(&evidence));
    evidence.exclusions = Some(Vec::new());
    evidence.burns = Some(vec![*old.as_bytes()]);
    assert!(bucket.index_retirement_known(&evidence));
    evidence.burns = Some(Vec::new());
    evidence.inventory.as_mut().unwrap().push(row.clone());
    evidence
        .inventory
        .as_mut()
        .unwrap()
        .sort_by_key(|row| row.pack_id);
    assert!(bucket.index_retirement_known(&evidence));
    evidence.exclusions = None;
    assert!(!bucket.index_retirement_known(&evidence));

    let read_error = bucket.get(&identity, None).await.unwrap_err();
    assert!(
        matches!(read_error.kind(), StoreErrorKind::Unsupported),
        "legacy unknown physical association returned {read_error:?}"
    );
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
    terrane_format::identity::Identity,
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
    let guard = super::held::SingleHeld::acquire(bucket).await.unwrap();
    let held = guard.destination();
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
    let artifacts =
        super::containers::admitted_artifacts(id, sealed.bytes(), &index_bytes).unwrap();
    crate::store::native_publication_effects::stage_container(
        &bucket.inner.fs,
        &observed,
        &artifacts,
    )
    .await
    .unwrap();
    let generation = bucket.next_generation(&catalog).await.unwrap();
    let index = PackIndexSnapshot::decode(&index_bytes, generation).unwrap();
    let inventory = super::containers::inventory_entry(id, sealed.bytes(), &index_bytes).unwrap();
    bucket
        .publish_pack_catalog(&held, &observed, catalog, index, inventory)
        .await
        .unwrap();
    drop(observed);
    drop(guard);
    (id, identity, index_bytes)
}
