//! Exercises real content operations after the physical owner's acknowledged Resume.

#[path = "content/objects.rs"]
mod objects;
#[path = "content/repeated.rs"]
mod repeated;

use std::{collections::BTreeMap, io};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::host_cache::NativeContentStore;
use terrane_sdk::store::{
    ByteRange, ChunkPosition, ChunkUpload, ContentStore, ContentUpload, IdentityPrefix,
    InvalidReason, MetaUpload, StoreErrorKind,
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
        store
            .has(std::slice::from_ref(&metadata))
            .await
            .map_err(io::Error::other)?,
        [true]
    );
    for candidate in [&identity, &metadata] {
        assert_eq!(
            store
                .list(&IdentityPrefix {
                    kind: candidate.kind(),
                    digest_prefix: candidate.digest().to_vec(),
                })
                .await
                .map_err(io::Error::other)?,
            std::slice::from_ref(candidate)
        );
    }
    assert!(matches!(store.list(&IdentityPrefix {
        kind: IdentityKind::Chunk,
        digest_prefix: vec![0; 33],
    }).await, Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest))));
    println!(
        "PASS actual native advisory listing finds ordinary chunk and metadata candidates and rejects malformed prefixes"
    );
    repeated::exercise(store, profile).await?;
    Ok(())
}

/// Exercises chunked objects separately from the finite 65-reference admission case.
pub(super) async fn exercise_objects(
    store: &NativeContentStore,
    profile: &ChunkProfile,
) -> io::Result<()> {
    objects::exercise(store, profile).await
}

/// Seals the canonical empty inline object without a fabricated source admission.
pub(super) async fn exercise_sealed(store: &NativeContentStore) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    use terrane_linux::host_cache::NativePreparedObject;
    use terrane_sdk::host::cache::ReassemblyMode;

    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &[])
        .map_err(io::Error::other)?;
    let NativePreparedObject::Sealed(object) = store
        .prepare_object(&identity, ReassemblyMode::Never)
        .await
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other("inline object escaped mandatory sealing"));
    };
    assert_eq!(object.identity(), &identity);
    assert_eq!(object.claim().plaintext_size(), 0);
    assert_eq!(object.handle().metadata()?.len(), 0);
    terrane_linux::verity::measure(object.handle())?;
    assert!(object.handle().write_at(b"forbidden", 0).is_err());
    assert_eq!(object.handle().metadata()?.len(), 0);

    println!(
        "INLINE_SEAL_STAGE actual empty sealed publication verified; completing cache handoff"
    );
    let report = object.into_cache().await.map_err(io::Error::other)?;
    assert_eq!(report.released_source_admissions, 0);
    let state = terrane_sdk::host::cache::CacheState::load(
        &terrane_sdk::store::TokioLocalFs,
        &store.ready().layout().layout().root().join("state/cache"),
        terrane_sdk::host::cache::StateLimits {
            bytes: 65536,
            records: 64,
        },
    )
    .await
    .map_err(io::Error::other)?
    .ok_or_else(|| io::Error::other("inline handoff lost its durable snapshot"))?;
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(state.leases.iter().any(|lease| {
        lease.owner.starts_with("publication-grace:")
            && lease.expires == report.release_grace_ends_at
            && state.pins.iter().any(|pin| {
                pin.owner == lease.owner && pin.hash == hash && pin.expires == lease.expires
            })
    }));
    println!(
        "PASS actual never-mode inline object is a read-only fs-verity inode with genuine completed cache handoff"
    );
    Ok(())
}
