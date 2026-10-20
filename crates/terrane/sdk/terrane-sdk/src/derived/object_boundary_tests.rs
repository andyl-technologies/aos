//! Exercises object-context chunk boundaries through the derived-data reader.

use super::*;
use terrane_format::{
    chunking::ChunkProfile,
    manifest::{ChunkRef, Manifest},
    tree_format::ContentRef,
};

fn store_file(store: &MemoryStore, profile: &ChunkProfile, plaintext: &[u8]) -> ContentRef {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .expect("actual plaintext identity");
    let encoded = crate::codec::encode_chunk(plaintext, profile.maximum(), 3, None)
        .expect("honest encoded chunk");
    store
        .bytes
        .lock()
        .expect("test store mutex")
        .insert(identity.digest().to_vec(), encoded);

    let chunk_digest = identity.terrane_v1_digest().expect("chunk digest");
    if plaintext.len() <= profile.minimum() {
        return ContentRef::Inline(chunk_digest);
    }

    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: chunk_digest,
            length: plaintext.len() as u64,
        }],
        hashes: BTreeMap::from([("blake3".into(), blake3::hash(plaintext).as_bytes().to_vec())]),
        media_type: None,
    };
    let identity = manifest
        .identity(profile)
        .expect("actual manifest identity");
    store.bytes.lock().expect("test store mutex").insert(
        identity.digest().to_vec(),
        manifest.encode(profile).expect("canonical manifest"),
    );

    ContentRef::Manifest(identity.terrane_v1_digest().expect("manifest digest"))
}

#[test]
fn derived_object_reads_reject_a_final_chunk_with_an_earlier_boundary() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut plaintext = vec![0; profile.maximum()];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-cdc-boundaries-v1\0");
    hasher.finalize_xof().fill(&mut plaintext);
    let first = profile.first_boundary(&plaintext);
    let prefix_length = 32;
    assert!(first > profile.minimum() && first < plaintext.len());
    assert!(prefix_length < first);

    for bytes in [&plaintext[..64], &plaintext[..first]] {
        let store = MemoryStore::default();
        let content = store_file(&store, &profile, bytes);
        let object = ready(StoreObject::open(
            &store,
            &NoDictionaries,
            &profile,
            content,
            bytes.len() as u64,
        ))
        .expect("open honest object");

        assert_eq!(
            ready(object.read_range(0, prefix_length)).expect("canonical final chunk prefix"),
            bytes[..prefix_length],
        );
    }

    let store = MemoryStore::default();
    let content = store_file(&store, &profile, &plaintext);
    let object = ready(StoreObject::open(
        &store,
        &NoDictionaries,
        &profile,
        content,
        plaintext.len() as u64,
    ))
    .expect("identity-verified manifest metadata");
    assert_eq!(store.reads.load(Ordering::Relaxed), 1);

    // A requested prefix entirely before the first cut must still reject the
    // enclosing noncanonical final chunk before returning any plaintext.
    assert!(matches!(
        ready(object.read_range(0, prefix_length)),
        Err(Error::Frame(crate::codec::FrameError::BoundaryMismatch))
    ));
    assert_eq!(store.reads.load(Ordering::Relaxed), 2);
}
