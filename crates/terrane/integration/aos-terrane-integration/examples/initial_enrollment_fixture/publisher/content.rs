//! Exercises real content operations after the physical owner's acknowledged Resume.

use std::{collections::BTreeMap, io};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::host_cache::NativeContentStore;
use terrane_sdk::store::{
    ByteRange, ChunkPosition, ChunkUpload, ContentStore, ContentUpload, InvalidReason, MetaUpload,
    StoreErrorKind,
};

pub(super) async fn exercise(store: &NativeContentStore, profile: &ChunkProfile) -> io::Result<()> {
    let plaintext = vec![23; 32769];
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    let upload = ChunkUpload {
        encoded: &encoded,
        identity: &identity,
        declared_plaintext_len: plaintext.len(),
        position: ChunkPosition::Final,
        profile,
    };

    assert_eq!(
        store
            .put(ContentUpload::Chunk(upload))
            .await
            .map_err(io::Error::other)?,
        identity
    );
    assert_eq!(
        store.get(&identity, None).await.map_err(io::Error::other)?,
        encoded
    );
    assert_eq!(
        store
            .get(
                &identity,
                Some(ByteRange {
                    start: 0,
                    length: 2
                })
            )
            .await
            .map_err(io::Error::other)?,
        [0, 23]
    );
    assert!(
        matches!(store.get(&identity, Some(ByteRange { start: u64::MAX, length: 2 })).await,
        Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Range(_))))
    );

    // An existing plaintext identity cannot excuse a newly invalid declaration
    // or nonfinal CDC position. Both refusals must preserve its original bytes.
    for (offered, expected_rule) in [
        (
            ChunkUpload {
                declared_plaintext_len: plaintext.len() + 1,
                ..upload
            },
            "CDC-12",
        ),
        (
            ChunkUpload {
                position: ChunkPosition::NonFinal,
                ..upload
            },
            "CDC-15",
        ),
    ] {
        assert!(matches!(store.put(ContentUpload::Chunk(offered)).await,
            Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }) if *rule_id == expected_rule)));
    }
    assert_eq!(
        store.get(&identity, None).await.map_err(io::Error::other)?,
        encoded
    );

    let absent = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"never admitted here")
        .map_err(io::Error::other)?;
    let empty = TERRANE_V1
        .calculate(IdentityKind::Chunk, &[])
        .map_err(io::Error::other)?;
    assert_eq!(
        store
            .has(&[identity.clone(), absent, empty.clone()])
            .await
            .map_err(io::Error::other)?,
        [true, false, true]
    );
    assert_eq!(
        store.get(&empty, None).await.map_err(io::Error::other)?,
        [0]
    );

    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
            length: plaintext.len() as u64,
        }],
        hashes: BTreeMap::from([(
            "blake3".to_owned(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(profile)
    .map_err(io::Error::other)?;
    let upload = MetaUpload::new(IdentityKind::Manifest, &manifest).map_err(io::Error::other)?;
    let metadata = store
        .put(ContentUpload::Meta(upload))
        .await
        .map_err(io::Error::other)?;
    assert_eq!(
        store.get(&metadata, None).await.map_err(io::Error::other)?,
        manifest
    );
    assert_eq!(
        store
            .put(ContentUpload::Meta(upload))
            .await
            .map_err(io::Error::other)?,
        metadata
    );
    assert_eq!(
        store.has(&[metadata]).await.map_err(io::Error::other)?,
        [true]
    );
    Ok(())
}
