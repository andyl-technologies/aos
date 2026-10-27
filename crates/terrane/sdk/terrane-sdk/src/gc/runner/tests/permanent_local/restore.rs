//! Exercises real collector extraction and fresh native admission beneath an owner.

use super::support::*;
use crate::gc::runner::copied_retirement_tests::support::{CopiedFixture, Residue};
use crate::pack::{MergedShard, PackId, RecordState};
use crate::store::{ChunkPosition, ChunkUpload, Clock, ContentStore, ContentUpload, RefStore};
use terrane_format::identity::Identity;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

async fn admit(fixture: &CopiedFixture, plaintext: &[u8]) -> Identity {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let mut encoded = vec![0];
    encoded.extend_from_slice(plaintext);
    assert_eq!(
        fixture
            .guard()
            .store()
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: &encoded,
                identity: &identity,
                declared_plaintext_len: plaintext.len(),
                position: ChunkPosition::Final,
                profile: &fixture.source.config.chunk_profile,
            }))
            .await
            .unwrap(),
        identity
    );
    identity
}

async fn row(fixture: &CopiedFixture, image: &Image, identity: &Identity) -> (PackId, RecordState) {
    let hash = identity.terrane_v1_digest().unwrap();
    let generation = image.capabilities.generation.unwrap();
    let prefix = hash[0];
    let bytes = tokio::fs::read(
        fixture
            .guard()
            .store()
            .root()
            .join(format!("objects/index/{generation}/{prefix}.idx")),
    )
    .await
    .unwrap();
    let shard = MergedShard::decode(&bytes, generation, prefix).unwrap();
    let entry = shard
        .entries()
        .iter()
        .find(|row| row.entry().hash() == &hash)
        .unwrap();
    (entry.pack(), entry.state())
}

#[tokio::test]
async fn permanent_local_restore_uses_fresh_secure_pack_and_preserves_burn_owner() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    install_source_index(&fixture).await;
    fixture.own().await;
    let before = image(&fixture).await;
    let root = fixture.guard().store().root();
    let source_pack = tokio::fs::read(root.join(fixture.pack.pack_key()))
        .await
        .unwrap();
    let source_index = tokio::fs::read(root.join(fixture.pack.index_key()))
        .await
        .unwrap();
    let branch = fixture
        .guard()
        .store()
        .ref_get("refs/heads/_/main")
        .await
        .unwrap();
    let mut recovery = takeover(&fixture, "permanent-fresh-placement").await;

    let fresh = recovery
        .restore(before.owner_key.as_deref().unwrap())
        .await
        .unwrap();

    assert_ne!(fresh, fixture.pack);
    let after = image(&fixture).await;
    assert_owner_retained(&before, &after);
    assert_eq!(
        after.capabilities.generation,
        before
            .capabilities
            .generation
            .map(|generation| generation + 1)
    );
    assert_eq!(
        after.manifest.inventory.as_ref().unwrap().len(),
        before.manifest.inventory.as_ref().unwrap().len() + 1
    );
    assert!(
        after
            .manifest
            .inventory
            .as_ref()
            .unwrap()
            .iter()
            .any(|row| row.pack_id == *fresh.as_bytes())
    );
    assert!(
        !after
            .manifest
            .burns
            .as_ref()
            .unwrap()
            .contains(fresh.as_bytes())
    );
    assert_eq!(
        tokio::fs::read(root.join(fixture.pack.pack_key()))
            .await
            .unwrap(),
        source_pack
    );
    assert_eq!(
        tokio::fs::read(root.join(fixture.pack.index_key()))
            .await
            .unwrap(),
        source_index
    );
    assert!(root.join(fresh.pack_key()).is_file());
    assert!(root.join(fresh.index_key()).is_file());
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, OLD_BODY).unwrap();
    let mut encoded = vec![0];
    encoded.extend_from_slice(OLD_BODY);
    assert_eq!(
        fixture.guard().store().get(&identity, None).await.unwrap(),
        encoded
    );
    let old_pack_identity = TERRANE_V1
        .calculate(IdentityKind::Pack, &source_pack)
        .unwrap();
    assert_eq!(
        fixture
            .guard()
            .store()
            .has(&[old_pack_identity])
            .await
            .unwrap(),
        vec![false]
    );
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        branch
    );
    drop(recovery);
    let fixture = reopen_checked(fixture, &after).await;
    assert_eq!(
        fixture.guard().store().get(&identity, None).await.unwrap(),
        encoded
    );
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_restore_preserves_fresh_serving_quarantine_and_unrelated_retirement() {
    let (fixture, unrelated) = CopiedFixture::new_with_unrelated_retirement(Residue::Pack).await;
    install_source_index(&fixture).await;
    let serving = admit(&fixture, OLD_BODY).await;
    let quarantined = admit(&fixture, b"unrelated permanent recovery quarantine").await;
    fixture.guard().store().exclude(&quarantined).await.unwrap();
    fixture.own().await;
    let before = image(&fixture).await;
    let serving_row = row(&fixture, &before, &serving).await;
    let quarantine_row = row(&fixture, &before, &quarantined).await;
    assert_eq!(serving_row.1, RecordState::Live);
    assert_eq!(quarantine_row.1, RecordState::Quarantine);
    assert_ne!(serving_row.0, fixture.pack);
    assert_ne!(unrelated.pack_id, *fixture.pack.as_bytes());
    assert!(
        before
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .contains(&unrelated)
    );
    let unrelated_inventory = before
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| row.pack_id == unrelated.pack_id)
        .unwrap()
        .clone();
    let mut recovery = takeover(&fixture, "permanent-preserving-recovery").await;

    let fresh = recovery
        .restore(before.owner_key.as_deref().unwrap())
        .await
        .unwrap();

    assert_ne!(fresh, fixture.pack);
    assert_ne!(fresh, serving_row.0);
    assert_ne!(*fresh.as_bytes(), unrelated.pack_id);
    let after = image(&fixture).await;
    assert_owner_retained(&before, &after);
    assert_eq!(row(&fixture, &after, &serving).await, serving_row);
    assert_eq!(row(&fixture, &after, &quarantined).await, quarantine_row);
    assert!(
        after
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .contains(&unrelated)
    );
    assert!(
        after
            .manifest
            .burns
            .as_ref()
            .unwrap()
            .contains(&unrelated.pack_id)
    );
    assert_eq!(
        after
            .manifest
            .inventory
            .as_ref()
            .unwrap()
            .iter()
            .find(|row| row.pack_id == unrelated.pack_id)
            .unwrap(),
        &unrelated_inventory
    );
    let mut encoded = vec![0];
    encoded.extend_from_slice(OLD_BODY);
    assert_eq!(
        fixture.guard().store().get(&serving, None).await.unwrap(),
        encoded
    );
    assert_eq!(
        fixture
            .guard()
            .store()
            .has(std::slice::from_ref(&quarantined))
            .await
            .unwrap(),
        vec![false]
    );
    drop(recovery);
    let fixture = reopen_checked(fixture, &after).await;
    assert_eq!(
        fixture.guard().store().get(&serving, None).await.unwrap(),
        encoded
    );
    assert_eq!(
        fixture
            .guard()
            .store()
            .has(std::slice::from_ref(&quarantined))
            .await
            .unwrap(),
        vec![false]
    );
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_missing_or_corrupt_source_never_publishes_recovery() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    fixture.own().await;
    for corrupt in [false, true] {
        if corrupt {
            install_source_index(&fixture).await;
            let path = fixture.guard().store().root().join(fixture.pack.pack_key());
            let mut bytes = tokio::fs::read(&path).await.unwrap();
            bytes[0] ^= 0xff;
            tokio::fs::write(&path, bytes).await.unwrap();
        }
        let owned = image(&fixture).await;
        let mut recovery = takeover(&fixture, "permanent-invalid-source").await;
        let before = image(&fixture).await;
        let lease = recovery.lease().clone();
        let started = fixture
            .source
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(
            recovery
                .restore(owned.owner_key.as_deref().unwrap())
                .await
                .is_err()
        );

        let finished = fixture
            .source
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let elapsed = finished.checked_sub(started).unwrap();
        let after = image(&fixture).await;
        assert_owner_retained(&owned, &after);
        assert_eq!(after.operation, before.operation);
        assert_eq!(after.pass, before.pass);
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(after.capabilities, before.capabilities);
        // The facade genuinely renews its own lease before extraction. That
        // authorized transition is the only selected successor on this refusal.
        let mut expected_state = before.state.clone();
        expected_state.revision += 1;
        assert_eq!(after.state, expected_state);
        let expected_lease = recovery.lease().clone();
        assert_eq!(expected_lease.holder, lease.holder);
        assert_eq!(expected_lease.epoch, lease.epoch);
        // Renewal samples epoch seconds independently before and during publish.
        let minimum_expiry = lease.expiry.checked_add(90).unwrap();
        assert!(expected_lease.expiry >= minimum_expiry);
        assert!(expected_lease.expiry <= minimum_expiry.checked_add(elapsed).unwrap());
        assert_eq!(
            terrane_format::gc::GcLease::decode(after.logical["gc/lease"].as_deref().unwrap())
                .unwrap(),
            expected_lease
        );
        assert!(
            recovery
                .restore(owned.owner_key.as_deref().unwrap())
                .await
                .is_err()
        );
        assert_eq!(image(&fixture).await.state, after.state);
        drop(recovery);
    }
    cleanup(fixture);
}
