//! Checks real full-D eventual physical deletion and fresh placement survival.

use super::support::*;
use crate::store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn full_d_and_current_lease_unlink_exact_triple_and_finish_done() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    assert!(
        collection
            .local_deletion_hint(&requested)
            .await
            .require()
            .is_none()
    );
    fixture.clock.enable_timer();

    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested.clone())
        .await
        .require();
    assert_eq!(owned.phase, terrane_format::gc::DeletePhase::Invalidated);
    assert!(owned.authorization.elapsed_ns >= windows().deletion() * 1_000_000_000);
    let mut cursor = crate::gc::runner::maintenance::local_deletion::LocalDeletionCursor::default();
    let lease_before = collection.lease().clone();
    assert!(
        collection
            .local_deletion_hints(&mut cursor, 0)
            .await
            .is_err()
    );
    assert!(
        collection
            .local_deletion_hints(&mut cursor, crate::gc::runner::maintenance::MAX_HINTS + 1)
            .await
            .is_err()
    );
    assert_eq!(collection.lease(), &lease_before);
    assert_eq!(cursor, Default::default());
    let pending = collection
        .local_deletion_hints(&mut cursor, 1)
        .await
        .require();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].operation_key,
        owned.authorization.operation_key()
    );
    assert_eq!(pending[0].exclusion.pack_id, owned.authorization.pack_id);
    assert_eq!(pending[0].exclusion.cycle, owned.authorization.cycle);
    assert_eq!(pending[0].exclusion.epoch, owned.authorization.epoch);
    assert_eq!(pending[0].phase, owned.phase);
    assert_eq!(
        collection.local_deletion_hint(&requested).await.require(),
        Some(pending[0].clone())
    );
    let mut other_epoch = requested.clone();
    other_epoch.epoch = other_epoch.epoch.checked_add(1).require();
    assert!(
        collection
            .local_deletion_hint(&other_epoch)
            .await
            .require()
            .is_none()
    );

    let done = collection
        .resume_local_delete(
            fixture.repository.coordinator(),
            &owned.authorization.operation_key(),
        )
        .await
        .require();

    assert_done(&fixture, &original, &owned, &done).await;
    let again = collection
        .resume_local_delete(
            fixture.repository.coordinator(),
            &owned.authorization.operation_key(),
        )
        .await
        .require();
    assert_eq!(again, done);
    let completed = collection
        .local_deletion_hints(&mut cursor, 1)
        .await
        .require();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].operation_key, pending[0].operation_key);
    assert_eq!(completed[0].exclusion, pending[0].exclusion);
    assert_eq!(completed[0].phase, terrane_format::gc::DeletePhase::Done);
    assert_eq!(
        collection.local_deletion_hint(&requested).await.require(),
        Some(completed[0].clone())
    );

    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn fresh_readmission_survives_old_container_deletion_and_reopen() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    let retired_pack = requested.pack_id;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    assert_eq!(owned.authorization.pack_id, retired_pack);
    let key = owned.authorization.operation_key();
    drop(collection);

    let plaintext = b"unreferenced genuine retirement candidate";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .require();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    let uploaded = fixture
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
        .require();
    assert_eq!(uploaded, identity);
    let head = root_readmission(&fixture).await;
    assert_ne!(head.commit, fixture.base.head.commit);
    let selected = image(&fixture).await;
    let fresh = selected
        .manifest
        .inventory
        .as_ref()
        .require()
        .iter()
        .filter(|row| row.pack_id != owned.authorization.pack_id)
        .map(|row| {
            (
                row.pack_id,
                std::fs::read(
                    fixture
                        .config
                        .root
                        .join(crate::pack::PackId::from_random_bytes(row.pack_id).pack_key()),
                )
                .require(),
            )
        })
        .collect::<Vec<_>>();
    assert!(!fresh.is_empty());
    // The changed signed root requires genuinely fresh current marks and a
    // new whole lease; old ownership remains immutable recovery data.
    let mut collection = fresh_collection(&fixture, 104).await;
    let done = collection
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require();

    assert_eq!(done.phase, terrane_format::gc::DeletePhase::Done);
    assert_eq!(done.authorization, owned.authorization);
    for path in &original.paths {
        assert!(!path.exists());
    }
    for (id, bytes) in &fresh {
        assert_eq!(
            std::fs::read(
                fixture
                    .config
                    .root
                    .join(crate::pack::PackId::from_random_bytes(*id).pack_key())
            )
            .require(),
            *bytes
        );
    }
    drop(collection);
    let reopened = fixture.base.reopen_repository().await;
    let fetched = reopened
        .coordinator()
        .guard()
        .store()
        .get(&identity, None)
        .await
        .require();
    assert_eq!(fetched, encoded);
    let envelope = terrane_format::codec::parse_envelope(&fetched).require();
    assert_eq!(envelope.codec, terrane_format::codec::Codec::Raw);
    assert_eq!(envelope.body, plaintext);
    drop(reopened);
    fixture.cleanup();
}

#[tokio::test]
async fn protected_done_status_is_available_before_marking_without_resurrection() {
    use crate::gc::runner::Restoration;
    use crate::store::Clock;

    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let done = collection
        .delete_local_pack(fixture.repository.coordinator(), requested.clone())
        .await
        .require();
    assert_done(&fixture, &original, &done, &done).await;
    let expiry = collection.lease().expiry;
    let ticks = fixture.clock.monotonic().as_secs();
    drop(collection);
    fixture.clock.set(expiry + 1, ticks + 1);

    let mut restoration = Restoration::start_next(
        fixture.guard(),
        &fixture.authority,
        "startup-Done-observation".into(),
        1_000,
        windows(),
    )
    .await
    .require();
    let selected_before = image(&fixture).await;
    let hint = restoration
        .local_deletion_hint(&requested)
        .await
        .require()
        .require();
    assert_eq!(hint.phase, terrane_format::gc::DeletePhase::Done);
    assert_eq!(hint.operation_key, done.authorization.operation_key());
    assert_eq!(hint.exclusion, requested);
    let mut wrong_epoch = requested.clone();
    wrong_epoch.epoch = wrong_epoch.epoch.checked_add(1).require();
    assert!(
        restoration
            .local_deletion_hint(&wrong_epoch)
            .await
            .require()
            .is_none()
    );
    let selected_after = image(&fixture).await;
    let mut before_logical = selected_before.logical;
    let mut after_logical = selected_after.logical;
    before_logical.remove("gc/lease");
    after_logical.remove("gc/lease");
    assert_eq!(after_logical, before_logical);
    assert_eq!(
        selected_after.state.loss_generation,
        selected_before.state.loss_generation
    );
    assert_eq!(selected_after.state.sources, selected_before.state.sources);
    for version in &done.authorization.artifacts {
        assert!(!fixture.config.root.join(&version.key).exists());
    }
    drop(restoration);
    fixture.cleanup();
}
