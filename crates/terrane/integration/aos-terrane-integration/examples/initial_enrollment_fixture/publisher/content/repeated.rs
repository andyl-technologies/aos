//! Checks repeated manifest references against actual bounded native grant custody.

use std::{collections::BTreeMap, io};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::host_cache::NativeContentStore;
use terrane_sdk::store::{
    ChunkPosition, ChunkUpload, ContentStore, ContentUpload, InvalidReason, MetaUpload,
    StoreErrorKind,
};

pub(super) async fn exercise(store: &NativeContentStore, profile: &ChunkProfile) -> io::Result<()> {
    // The real owner allows 64 policy records. Sixty-five references to one
    // immutable source must retain one grant while checking every position.
    const REFERENCES: usize = 65;
    let plaintext = natural_chunk(profile)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    let upload = ChunkUpload {
        encoded: &encoded,
        identity: &identity,
        declared_plaintext_len: plaintext.len(),
        position: ChunkPosition::NonFinal,
        profile,
    };
    store
        .put(ContentUpload::Chunk(upload))
        .await
        .map_err(io::Error::other)?;

    let digest = identity.terrane_v1_digest().map_err(io::Error::other)?;
    let mut hasher = blake3::Hasher::new();
    for _ in 0..REFERENCES {
        hasher.update(&plaintext);
    }
    let manifest = Manifest {
        size: (plaintext.len() * REFERENCES) as u64,
        chunks: vec![
            ChunkRef {
                digest,
                length: plaintext.len() as u64
            };
            REFERENCES
        ],
        hashes: BTreeMap::from([("blake3".to_owned(), hasher.finalize().as_bytes().to_vec())]),
        media_type: None,
    };
    let canonical = manifest.encode(profile).map_err(io::Error::other)?;
    let upload = MetaUpload::new(IdentityKind::Manifest, &canonical).map_err(io::Error::other)?;
    let stored = store
        .put(ContentUpload::Meta(upload))
        .await
        .map_err(io::Error::other)?;
    assert_eq!(
        store.get(&stored, None).await.map_err(io::Error::other)?,
        canonical
    );

    // Reusing that grant cannot excuse a different length in the last position.
    let mut invalid = manifest;
    invalid.size -= 1;
    invalid.chunks[REFERENCES - 1].length -= 1;
    let canonical = invalid.encode(profile).map_err(io::Error::other)?;
    let upload = MetaUpload::new(IdentityKind::Manifest, &canonical).map_err(io::Error::other)?;
    assert!(matches!(store.put(ContentUpload::Meta(upload)).await,
        Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-12" }))));
    assert_eq!(
        store.get(&identity, None).await.map_err(io::Error::other)?,
        encoded
    );
    println!(
        "PASS actual 65-reference manifest uses bounded original native grants and checks every declared position"
    );
    Ok(())
}

fn natural_chunk(profile: &ChunkProfile) -> io::Result<Vec<u8>> {
    // Independent deterministic input finds a genuine boundary below the real
    // owner's 2 MiB read bound, without changing the registered chunk profile.
    for seed in 1..=16u64 {
        let mut state = seed;
        let mut bytes = Vec::with_capacity(2 * 1024 * 1024);
        for _ in 0..bytes.capacity() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        let boundary = profile.first_boundary(&bytes);
        bytes.truncate(boundary);
        if profile.valid_nonfinal_chunk(&bytes) {
            return Ok(bytes);
        }
    }
    Err(io::Error::other(
        "no natural chunk boundary within native fixture read limit",
    ))
}
