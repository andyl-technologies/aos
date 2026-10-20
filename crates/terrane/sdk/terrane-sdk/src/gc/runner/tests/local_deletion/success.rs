//! Checks real full-D eventual physical deletion and fresh placement survival.

use super::support::*;
use crate::store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn full_d_and_current_lease_unlink_exact_triple_and_finish_done() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();

    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    assert_eq!(owned.phase, terrane_format::gc::DeletePhase::Invalidated);
    assert!(owned.authorization.elapsed_ns >= windows().deletion() * 1_000_000_000);
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
