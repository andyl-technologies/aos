//! Checks ordinary dictionary fetching, dependent decoding, and identity failures.

use super::*;
use crate::codec::{FrameError, encode_chunk};
use terrane_core::{
    chunking::ChunkProfile,
    codec::{Codec, EncodedChunk, encode_envelope, parse_envelope},
    tree_format::ContentRef,
};

fn store_chunk(store: &MemoryStore, plaintext: &[u8], dictionary: Option<&[u8]>) -> Identity {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .expect("standalone chunk identity");
    let encoded = encode_chunk(plaintext, 128 * 1024, 3, dictionary).expect("dictionary codec");
    store
        .bytes
        .lock()
        .expect("test mutex")
        .insert(identity.digest().to_vec(), encoded);
    identity
}

#[test]
fn named_dictionary_fetch_verifies_plaintext_before_object_hashing() {
    let store = MemoryStore::default();
    let profile =
        ChunkProfile::new(16 * 1024, 64 * 1024, 128 * 1024, 48, 1, [3; 32]).expect("test profile");
    let dictionary = b"recurring content class vocabulary and common prefix ".repeat(64);
    let dictionary_identity = store_chunk(&store, &dictionary, None);
    let plaintext = b"recurring content class vocabulary and common prefix payload\n".repeat(128);
    let identity = store_chunk(&store, &plaintext, Some(&dictionary));
    let encoded = store
        .bytes
        .lock()
        .expect("test mutex")
        .get(identity.digest())
        .expect("stored object")
        .clone();
    let digest = dictionary_identity
        .terrane_v1_digest()
        .expect("dictionary digest");
    assert_eq!(
        parse_envelope(&encoded).expect("object envelope").codec,
        Codec::ZstdDictionary(digest)
    );

    let dictionaries = StoreDictionaries::new(&store, &profile);
    assert_eq!(
        ready(dictionaries.resolve(digest)).expect("verified dictionary"),
        dictionary
    );
    let object = ready(StoreObject::open(
        &store,
        &dictionaries,
        &profile,
        ContentRef::Inline(identity.terrane_v1_digest().expect("object digest")),
        plaintext.len() as u64,
    ))
    .expect("dictionary-coded inline object");
    let computed = ready(compute(
        &object,
        &[AttributeName::Sha256, AttributeName::Magic],
    ))
    .expect("verified dictionary object plaintext");
    let mut expected = terrane_core::derived::PlaintextHashes::new(plaintext.len() as u64);
    expected.update(&plaintext).expect("full plaintext");
    assert_eq!(
        computed,
        vec![
            AttributeValue::Sha256(expected.finish().expect("hashes").sha256),
            AttributeValue::Magic(Magic::Text)
        ]
    );

    store.bytes.lock().expect("test mutex").insert(
        dictionary_identity.digest().to_vec(),
        encode_envelope(EncodedChunk {
            codec: Codec::Raw,
            body: b"wrong dictionary",
        }),
    );
    assert!(ready(compute(&object, &[AttributeName::Sha256])).is_err());
}

#[test]
fn dictionary_dependencies_are_verified_and_cycles_are_rejected() {
    let store = MemoryStore::default();
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let base = b"dictionary dependency vocabulary ".repeat(64);
    store_chunk(&store, &base, None);
    let parent = b"dictionary dependency vocabulary extended words ".repeat(64);
    let identity = store_chunk(&store, &parent, Some(&base));
    let digest = identity
        .terrane_v1_digest()
        .expect("parent dictionary digest");
    let dictionaries = StoreDictionaries::new(&store, &profile);
    assert_eq!(
        ready(dictionaries.resolve(digest)).expect("verified dependency chain"),
        parent
    );

    // Replace just the referenced identity to make a valid frame's dependency
    // point back to itself; no decompression or plaintext may be exposed.
    let mut encoded = store
        .bytes
        .lock()
        .expect("test mutex")
        .get(identity.digest())
        .expect("parent envelope")
        .clone();
    assert_eq!(encoded[0], 2);
    encoded[1..33].copy_from_slice(&digest);
    store
        .bytes
        .lock()
        .expect("test mutex")
        .insert(identity.digest().to_vec(), encoded);
    assert!(matches!(
        ready(dictionaries.resolve(digest)),
        Err(Error::Derived(terrane_core::derived::Error::InvalidValue))
    ));
}

#[test]
fn oversized_dictionary_is_rejected_before_decompression() {
    let store = MemoryStore::default();
    let profile = ChunkProfile::new(16, 64, 128, 48, 1, [3; 32]).expect("test profile");
    let plaintext = vec![b'a'; 129];
    let identity = store_chunk(&store, &plaintext, None);
    let dictionaries = StoreDictionaries::new(&store, &profile);
    assert!(matches!(
        ready(dictionaries.resolve(identity.terrane_v1_digest().expect("digest"))),
        Err(Error::Frame(FrameError::Envelope(_)))
    ));
}
