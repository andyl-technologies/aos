//! Checks stale Live rows while retaining genuine native retirement authority.
//!
//! The ordinary successor changes only nominal index rows. Its exclusion comes
//! from actual current marking, age qualification and native retirement ACK.

use super::*;
use crate::pack::MergedShard;
use std::collections::BTreeMap;

/// Checks fresh verified placement without reviving an excluded physical pack.
///
/// # Panics
/// Panics when actual retirement/publication or an owning invariant fails.
pub(in crate::bucket) async fn physical_exclusion_overrides_live_rows_during_fresh_admission() {
    let fixture = Fixture::new().await;
    let bucket = fixture.guard().store().clone();
    let body = b"live row cannot acknowledge a physically retired placement";
    let other = b"another old member remains physically excluded";
    let quarantined = b"identity quarantine remains sticky through stale rows";
    let identity = chunk_identity(body);
    let other_identity = chunk_identity(other);
    let quarantined_identity = chunk_identity(quarantined);
    let (old, _, _) = publish_members_with_index_alias(&bucket, &[body, other, quarantined]).await;
    bucket.exclude(&quarantined_identity).await.unwrap();
    let before_retirement = bucket.catalog().await.unwrap();
    let captured = before_retirement
        .shards
        .iter()
        .flat_map(|shard| {
            terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap()
        })
        .map(|record| (record.record.hash, record))
        .collect::<BTreeMap<_, _>>();
    let inventory = before_retirement
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|entry| entry.pack_id == *old.as_bytes())
        .unwrap();
    let (pack_bytes, index_bytes) = bucket.verified_container(inventory).await.unwrap();
    let pack_identity = TERRANE_V1
        .calculate(IdentityKind::Pack, &pack_bytes)
        .unwrap();
    let index_identity = TERRANE_V1
        .calculate(IdentityKind::Index, &index_bytes)
        .unwrap();
    let (collection, tombstone) = retire(&fixture, old).await;
    let trash_key = BucketKey::parse(&format!("trash/{}/{old}", tombstone.cycle)).unwrap();
    let exclusion = PackExclusion {
        pack_id: tombstone.pack,
        cycle: tombstone.cycle,
        epoch: tombstone.epoch,
    };
    assert_eq!(
        bucket.read_optional(&trash_key).await.unwrap(),
        Some(tombstone.encode())
    );

    // Preserve the actual exclusion and all presently Live rows. Only old
    // Tombstone rows regain their captured nominal Live form; physical lookup
    // remains fenced by the genuine selected retirement association.
    let holder = super::super::held::SingleHeld::acquire(&bucket)
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_publication().await.unwrap();
    let selected_before = bucket.selected_publication_locked().await.unwrap();
    let retired = bucket.catalog().await.unwrap();
    assert_eq!(retired.exclusions, Some(vec![exclusion.clone()]));
    let retired_live = retired
        .shards
        .iter()
        .flat_map(|shard| {
            terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap()
        })
        .filter(|record| record.state == RecordState::Live as u8)
        .collect::<Vec<_>>();
    let retained_inventory = retired.inventory.clone();
    let retained_burns = retired.burns.clone();
    let generation = bucket.next_generation(&retired).await.unwrap();
    let mut restored_rows = 0;
    let shards = retired
        .shards
        .iter()
        .map(|shard| {
            let mut records =
                terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap();
            for record in &mut records {
                if record.pack == *old.as_bytes() && record.state == RecordState::Tombstone as u8 {
                    let original = captured.get(&record.record.hash).unwrap();
                    assert_eq!(original.state, RecordState::Live as u8);
                    assert_eq!(original.pack, record.pack);
                    record.state = original.state;
                    assert_eq!(record, original);
                    restored_rows += 1;
                }
            }
            MergedShard::decode(
                &terrane_format::pack_format::encode_shard(&records),
                generation,
                shard.shard(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(restored_rows >= 2);
    bucket
        .publish_shards_held(&held, &observed, retired, generation, &shards)
        .await
        .unwrap();
    let selected_stale = bucket.selected_publication_locked().await.unwrap();
    let mut expected_state = selected_before.state.clone();
    expected_state.revision += 1;
    assert_eq!(selected_stale.state, expected_state);
    for (key, value) in &selected_before.logical {
        if key != "CAPABILITIES" {
            assert_eq!(selected_stale.logical.get(key), Some(value));
        }
    }
    let stale = bucket.catalog().await.unwrap();
    assert_eq!(stale.inventory, retained_inventory);
    assert_eq!(stale.exclusions, Some(vec![exclusion.clone()]));
    assert_eq!(stale.burns, retained_burns);
    let stale_records = stale
        .shards
        .iter()
        .flat_map(|shard| {
            terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard()).unwrap()
        })
        .collect::<Vec<_>>();
    for record in &retired_live {
        assert!(stale_records.contains(record));
    }
    let row = stale
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_eq!(row.state(), RecordState::Live);
    assert_eq!(row.pack(), old);
    drop(observed);
    drop(held);
    drop(holder);

    assert_eq!(
        bucket
            .has(&[
                identity.clone(),
                other_identity.clone(),
                quarantined_identity.clone(),
                pack_identity.clone(),
                index_identity.clone()
            ])
            .await
            .unwrap(),
        vec![false; 5]
    );
    for unavailable in [&identity, &other_identity, &pack_identity, &index_identity] {
        assert!(matches!(
            bucket.get(unavailable, None).await.unwrap_err().kind(),
            StoreErrorKind::Absent(_)
        ));
        assert!(
            !bucket
                .published_identities(unavailable.kind())
                .await
                .unwrap()
                .contains(unavailable)
        );
    }

    bucket
        .put(upload(
            &raw(body),
            &identity,
            body.len(),
            &fixture.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    assert_eq!(bucket.get(&identity, None).await.unwrap(), raw(body));
    let fresh = bucket.catalog().await.unwrap();
    assert_eq!(fresh.exclusions, Some(vec![exclusion.clone()]));
    assert_eq!(fresh.burns, retained_burns);
    for entry in retained_inventory.as_ref().unwrap() {
        assert!(fresh.inventory.as_ref().unwrap().contains(entry));
    }
    let placement = fresh
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_eq!(placement.state(), RecordState::Live);
    assert_ne!(placement.pack(), old);
    let other_row = fresh
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &other_identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_eq!(other_row.state(), RecordState::Live);
    assert_eq!(other_row.pack(), old);
    assert_eq!(
        bucket
            .read_optional(&BucketKey::parse(&old.pack_key()).unwrap())
            .await
            .unwrap(),
        Some(pack_bytes)
    );
    assert_eq!(
        bucket
            .read_optional(&BucketKey::parse(&old.index_key()).unwrap())
            .await
            .unwrap(),
        Some(index_bytes)
    );
    let quarantine = fresh
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &quarantined_identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_eq!(quarantine.state(), RecordState::Quarantine);
    assert_eq!(
        bucket.read_optional(&trash_key).await.unwrap(),
        Some(tombstone.encode())
    );
    assert_eq!(
        bucket
            .has(&[
                identity.clone(),
                other_identity.clone(),
                quarantined_identity.clone(),
                pack_identity.clone(),
                index_identity.clone()
            ])
            .await
            .unwrap(),
        vec![true, false, false, false, false]
    );
    let selected_fresh = bucket.selected_publication_locked().await.unwrap();
    let mut expected_state = selected_stale.state.clone();
    expected_state.revision += 1;
    // Replacing an exact nominal Live row retains the ordinary Raw loss fence.
    expected_state.loss_generation += 1;
    assert_eq!(selected_fresh.state, expected_state);
    for (key, value) in &selected_stale.logical {
        if key != "CAPABILITIES" {
            assert_eq!(selected_fresh.logical.get(key), Some(value));
        }
    }

    // Active startup may publish only a changed capability-probe timestamp.
    let mut expected_reopened_state = selected_fresh.state.clone();
    let mut expected_reopened_logical = selected_fresh.logical.clone();
    let capability_bytes = selected_fresh
        .logical
        .get("CAPABILITIES")
        .unwrap()
        .as_ref()
        .unwrap();
    let mut expected_capabilities =
        terrane_format::bucket::BucketCapabilities::decode(capability_bytes).unwrap();
    expected_capabilities.probed_at = fixture
        .clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected_capability_bytes = expected_capabilities.encode().unwrap();
    if *capability_bytes != expected_capability_bytes {
        expected_reopened_state.revision += 1;
        expected_reopened_logical.insert("CAPABILITIES".into(), Some(expected_capability_bytes));
    }

    let reopened = FileBucket::open(
        fixture.config.clone(),
        fixture.fs.clone(),
        fixture.clock.retain_native_clock().unwrap(),
        crate::gc::runner::fixture::Validator,
    )
    .await
    .unwrap();
    let reopened_selected = reopened.selected_publication_locked().await.unwrap();
    assert_eq!(reopened_selected.state, expected_reopened_state);
    assert_eq!(reopened_selected.logical, expected_reopened_logical);
    assert_eq!(reopened.get(&identity, None).await.unwrap(), raw(body));
    assert_eq!(
        reopened.catalog().await.unwrap().exclusions,
        Some(vec![exclusion])
    );
    assert_eq!(
        reopened.read_optional(&trash_key).await.unwrap(),
        Some(tombstone.encode())
    );
    assert_eq!(
        reopened
            .has(&[
                identity,
                other_identity,
                quarantined_identity,
                pack_identity,
                index_identity
            ])
            .await
            .unwrap(),
        vec![true, false, false, false, false]
    );
    drop(reopened);
    drop(bucket);
    drop(collection);
    fixture.cleanup();
}
