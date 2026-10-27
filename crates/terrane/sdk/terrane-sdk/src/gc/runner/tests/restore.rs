//! Qualifies native pre-ownership restore with genuine creators and current sessions.
//!
//! These witnesses grant no deletion, creator or age authority from Trash or
//! decoded journals. The exact active tuple only selects the requested pack.

use super::*;
use crate::store::native_publication_effects::collection::test_fs::RetirementPhase;
use crate::store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload};
use crate::store::{EffectFault, StoreErrorKind};
use terrane_format::bucket::PackExclusion;
mod support;
use support::*;

mod missing_trash;
mod session;

mod copy;
use copy::copied;

fn selector(trash: &terrane_format::gc::Tombstone) -> PackExclusion {
    PackExclusion {
        pack_id: trash.pack,
        cycle: trash.cycle,
        epoch: trash.epoch,
    }
}

#[tokio::test]
async fn gc_restore_native_unknown_trash_age_restores_exact_generation() {
    let fixture = Fixture::new().await;
    let (mut collection, id, trash) = retired(&fixture).await;
    let before = image(&fixture).await;
    let key = format!("trash/{}/{id}", trash.cycle);
    let original_journal = tokio::fs::read(journal(&fixture, &key)).await.unwrap();
    // Unknown physical age has no bearing on pre-ownership restoration.
    tokio::fs::remove_file(fixture.config.root.join(&key))
        .await
        .unwrap();
    assert!(collection.restore_pack(selector(&trash)).await.unwrap());
    assert_restored(&fixture, &before, id).await;
    assert_orphan_live(&fixture, id).await;
    assert_eq!(
        tokio::fs::read(journal(&fixture, &key)).await.unwrap(),
        original_journal
    );
    assert!(!collection.restore_pack(selector(&trash)).await.unwrap());
}

#[tokio::test]
async fn gc_restore_native_metadata_only_pair_handles_imported_unknown() {
    {
        let source = Fixture::new().await;
        let (collection, id, trash) = retired(&source).await;
        drop(collection);
        let destination = copied(&source, id, false).await;
        let before = image(&destination).await;
        let data_paths = before
            .manifest
            .inventory
            .as_ref()
            .unwrap()
            .iter()
            .map(|row| crate::pack::PackId::from_random_bytes(row.pack_id))
            .collect::<Vec<_>>();
        let mut data = Vec::new();
        for id in data_paths {
            let bytes = tokio::fs::read(destination.config.root.join(id.index_key()))
                .await
                .unwrap();
            if bytes[6] & 2 == 0 {
                data.push(destination.config.root.join(id.pack_key()));
            }
        }
        destination.fs.forbid_data_body_reads(&data).unwrap();
        let mut maintenance = Restoration::start(
            destination.guard(),
            &destination.authority,
            "copied-maintenance".into(),
            1_000,
            52,
            windows(),
        )
        .await
        .unwrap();
        assert!(maintenance.restore_pack(selector(&trash)).await.unwrap());
        assert_restored(&destination, &before, id).await;
        assert_orphan_live(&destination, id).await;
        for key in [
            id.pack_key(),
            id.index_key(),
            format!("trash/{}/{id}", trash.cycle),
        ] {
            assert!(!journal(&destination, &key).exists());
        }
    }
    let fixture = Fixture::new().await;
    let (mut collection, id, trash) = retired(&fixture).await;
    for key in [
        id.pack_key(),
        id.index_key(),
        format!("trash/{}/{id}", trash.cycle),
    ] {
        tokio::fs::remove_file(journal(&fixture, &key))
            .await
            .unwrap();
    }
    let before = image(&fixture).await;
    assert!(collection.restore_pack(selector(&trash)).await.unwrap());
    assert_restored(&fixture, &before, id).await;
    for key in [
        id.pack_key(),
        id.index_key(),
        format!("trash/{}/{id}", trash.cycle),
    ] {
        assert!(!journal(&fixture, &key).exists());
    }
}

#[tokio::test]
async fn gc_restore_native_stale_and_unknown_incarnations_never_publish() {
    let fixture = Fixture::new().await;
    let (mut collection, id, trash) = retired(&fixture).await;
    let before = image(&fixture).await;
    for changed in [
        PackExclusion {
            epoch: trash.epoch + 1,
            ..selector(&trash)
        },
        PackExclusion {
            cycle: trash.cycle + 1,
            ..selector(&trash)
        },
        PackExclusion {
            pack_id: [0x73; 16],
            ..selector(&trash)
        },
    ] {
        assert!(!collection.restore_pack(changed).await.unwrap());
        let after = image(&fixture).await;
        assert_eq!(after.cap, before.cap);
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(after.state.loss_generation, before.state.loss_generation);
    }
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    assert!(fixture.config.root.join(id.pack_key()).exists());
}

#[tokio::test]
async fn gc_restore_native_missing_pair_never_advertises_old_placement() {
    for index in [false, true] {
        let fixture = Fixture::new().await;
        let (mut collection, id, trash) = retired(&fixture).await;
        let path = fixture
            .config
            .root
            .join(if index { id.index_key() } else { id.pack_key() });
        tokio::fs::remove_file(path).await.unwrap();
        let before = image(&fixture).await;
        assert!(collection.restore_pack(selector(&trash)).await.is_err());
        let after = image(&fixture).await;
        assert_eq!(after.cap, before.cap);
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(after.state.loss_generation, before.state.loss_generation);
        assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    }
}

#[tokio::test]
async fn gc_restore_native_preserves_fresh_live_quarantine_and_selected_values() {
    for quarantine in [false, true] {
        let fixture = Fixture::new().await;
        let (mut collection, id, trash) = retired(&fixture).await;
        let plaintext = b"unreferenced genuine retirement candidate";
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .unwrap();
        if quarantine {
            fixture.guard().store().exclude(&identity).await.unwrap();
        } else {
            let encoded =
                terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
                    codec: terrane_format::codec::Codec::Raw,
                    body: plaintext,
                });
            fixture
                .guard()
                .store()
                .put(ContentUpload::Chunk(ChunkUpload {
                    encoded: &encoded,
                    identity: &identity,
                    declared_plaintext_len: plaintext.len(),
                    position: ChunkPosition::Final,
                    profile: &fixture.config.chunk_profile,
                }))
                .await
                .unwrap();
        }
        fixture
            .publish_notes(&[("refs/notes/profiles/_/restore", b"preserved whole notes")])
            .await;
        let before = image(&fixture).await;
        let hash = identity.terrane_v1_digest().unwrap();
        let mut selected_row = None;
        for shard in &before.manifest.shards {
            let key = format!(
                "objects/index/{}/{}.idx",
                before.manifest.generation, shard.shard
            );
            for row in terrane_format::pack_format::decode_shard(
                before.logical[&key].as_deref().unwrap(),
                u8::try_from(shard.shard).unwrap(),
            )
            .unwrap()
            {
                if row.record.hash == hash {
                    selected_row = Some(row);
                }
            }
        }
        let selected_row = selected_row.unwrap();
        assert_ne!(
            selected_row.state,
            crate::pack::RecordState::Tombstone as u8
        );
        if !quarantine {
            assert_ne!(selected_row.pack, *id.as_bytes());
        }
        assert!(collection.restore_pack(selector(&trash)).await.unwrap());
        assert_restored(&fixture, &before, id).await;
        let after = image(&fixture).await;
        let key = format!(
            "objects/index/{}/{}.idx",
            after.manifest.generation, hash[0]
        );
        let restored = terrane_format::pack_format::decode_shard(
            after.logical[&key].as_deref().unwrap(),
            hash[0],
        )
        .unwrap();
        assert_eq!(
            restored.iter().find(|row| row.record.hash == hash),
            Some(&selected_row)
        );
        assert_eq!(
            fixture.guard().store().has(&[identity]).await.unwrap(),
            vec![!quarantine]
        );
    }
}

#[tokio::test]
async fn gc_restore_native_sync_and_noop_results_never_acknowledge() {
    for position in 0..4 {
        let fixture = Fixture::new().await;
        let (mut collection, id, trash) = retired(&fixture).await;
        if position == 0 {
            fixture.fs.noop_next_retirement_barrier();
        } else {
            let fault = match position {
                1 => EffectFault::AfterFileSync,
                2 => EffectFault::BeforeDirectorySync,
                3 => EffectFault::AfterDirectorySyncAt(fixture.config.root.clone()),
                _ => unreachable!(),
            };
            fixture
                .fs
                .fail_next_retirement(RetirementPhase::Barrier, fault, true);
        }
        let error = collection.restore_pack(selector(&trash)).await.unwrap_err();
        assert_eq!(failure_kind(&error), &StoreErrorKind::Unsupported);
        fixture.fs.assert_retirement_hook_consumed();
        assert_eq!(fixture.fs.data_body_read_attempts(), 0);
        assert!(fixture.config.root.join(id.pack_key()).exists());
        assert!(fixture.config.root.join(id.index_key()).exists());
        // A selected visible successor is possible. It cannot substitute for the
        // missing closed acknowledgment, and this failed session cannot continue.
        assert!(collection.restore_pack(selector(&trash)).await.is_err());
    }
}

#[tokio::test]
async fn gc_restore_native_burn_owner_and_deleteowned_refuse() {
    {
        let source = Fixture::new().await;
        let (collection, id, trash) = retired(&source).await;
        drop(collection);
        let destination = copied(&source, id, true).await;
        let before = image(&destination).await;
        let owner = before
            .state
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .find(|owner| owner.pack == *id.as_bytes())
            .unwrap();
        assert_eq!(
            owner.selection,
            terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility
        );
        let mut maintenance = Restoration::start(
            destination.guard(),
            &destination.authority,
            "burn-refusal".into(),
            1_000,
            52,
            windows(),
        )
        .await
        .unwrap();
        let error = maintenance
            .restore_pack(selector(&trash))
            .await
            .unwrap_err();
        assert_eq!(failure_kind(&error), &StoreErrorKind::Unsupported);
        let after = image(&destination).await;
        assert_eq!(after.cap, before.cap);
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(after.state.burn_owners, before.state.burn_owners);
    }
    // These are canonical encoded refusal inputs. They are deliberately not
    // described as a genuinely selected permanent-delete ownership receipt.
    for key_index in 0..3 {
        let fixture = Fixture::new().await;
        let (mut collection, id, trash) = retired(&fixture).await;
        let keys = [
            id.pack_key(),
            id.index_key(),
            format!("trash/{}/{id}", trash.cycle),
        ];
        let path = journal(&fixture, &keys[key_index]);
        let mut record =
            terrane_format::gc::CreationJournal::decode(&tokio::fs::read(&path).await.unwrap())
                .unwrap();
        let terrane_format::gc::JournalState::Committed {
            binding,
            file_identity,
        } = record.state
        else {
            panic!("expected genuine baseline creator");
        };
        record.state = terrane_format::gc::JournalState::DeleteOwned {
            binding,
            file_identity,
            authorization: [0x37; 32],
            operation_key: format!("gc/{}/delete/{id}/{}", trash.cycle, "37".repeat(32)),
        };
        let bytes = record.encode().unwrap();
        assert_eq!(
            terrane_format::gc::CreationJournal::decode(&bytes).unwrap(),
            record
        );
        tokio::fs::write(path, bytes).await.unwrap();
        let before = image(&fixture).await;
        let error = collection.restore_pack(selector(&trash)).await.unwrap_err();
        // The synthetic journal key cannot supply the missing protected intent.
        assert_eq!(
            failure_kind(&error),
            &StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName("publication".into()))
        );
        let after = image(&fixture).await;
        assert_eq!(after.cap, before.cap);
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(after.state.burn_owners, before.state.burn_owners);
        assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    }
}

#[tokio::test]
async fn gc_restore_native_reopen_and_fresh_cycle_make_old_trash_stale() {
    restore_meta_after_reopen().await;
    let fixture = Fixture::new().await;
    let (collection, id, trash) = retired(&fixture).await;
    let expiry = collection.lease().expiry;
    drop(collection);
    fixture.clock.set(expiry + 1, expiry - 99);
    let reopened = fixture.reopen_repository().await;
    let mut maintenance = Restoration::start(
        reopened.coordinator().guard(),
        &fixture.authority,
        "reopened-maintenance".into(),
        1_000,
        52,
        windows(),
    )
    .await
    .unwrap();
    let before = image(&fixture).await;
    assert!(maintenance.restore_pack(selector(&trash)).await.unwrap());
    assert_restored(&fixture, &before, id).await;
    assert!(!maintenance.restore_pack(selector(&trash)).await.unwrap());
    assert!(
        fixture
            .config
            .root
            .join(format!("trash/{}/{id}", trash.cycle))
            .exists()
    );
    let expiry = maintenance.lease().expiry;
    drop(maintenance);
    fixture.clock.set(expiry + 1, expiry - 99);
    let mut next = Collection::start(
        reopened.coordinator().guard(),
        &fixture.authority,
        "fresh-later-cycle".into(),
        1_000,
        53,
        windows(),
    )
    .await
    .unwrap();
    next.mark_batch(32).await.unwrap();
    next.finish_mark().await.unwrap();
    let later = next
        .retire_one(reopened.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(later.pack, trash.pack);
    assert_ne!(later.cycle, trash.cycle);
    assert_ne!(later.epoch, trash.epoch);
    assert!(!next.restore_pack(selector(&trash)).await.unwrap());
    assert!(next.restore_pack(selector(&later)).await.unwrap());
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}

#[tokio::test]
async fn gc_restore_native_each_handoff_rechecks_current_controls_and_pair() {
    handoffs::changes_refuse().await;
}

#[tokio::test]
async fn gc_restore_native_cancelled_worker_retains_exclusions() {
    handoffs::cancellation_refuses().await;
}

mod handoffs;
