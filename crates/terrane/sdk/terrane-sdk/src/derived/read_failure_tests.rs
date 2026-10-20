//! Distinguishes dictionary read failures from checked signed-value contradictions.

use super::*;
use crate::codec::encode_chunk;
use terrane_format::{
    chunking::ChunkProfile,
    codec::{Codec, parse_envelope},
};

#[derive(Default)]
struct RecordingQuarantine {
    identities: Mutex<Vec<Identity>>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl AttributeQuarantine for RecordingQuarantine {
    async fn exclude_attribute(&self, identity: &Identity) -> Result<(), Error> {
        self.identities
            .lock()
            .expect("fixture mutex")
            .push(identity.clone());
        Ok(())
    }
}

fn store_chunk(store: &MemoryStore, plaintext: &[u8], dictionary: Option<&[u8]>) -> Identity {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .expect("standalone chunk identity");
    let encoded = encode_chunk(plaintext, 128 * 1024, 3, dictionary).expect("chunk codec");
    store
        .bytes
        .lock()
        .expect("fixture mutex")
        .insert(identity.digest().to_vec(), encoded);
    identity
}

#[test]
fn cyclic_dictionary_read_preserves_signed_attribute_until_verified_retry() {
    let store = MemoryStore::default();
    let profile =
        ChunkProfile::new(16 * 1024, 64 * 1024, 128 * 1024, 48, 1, [3; 32]).expect("profile");
    let base = b"dictionary dependency vocabulary ".repeat(64);
    let base_identity = store_chunk(&store, &base, None);
    let dictionary = b"dictionary dependency vocabulary extended words ".repeat(64);
    let dictionary_identity = store_chunk(&store, &dictionary, Some(&base));
    let dictionary_digest = dictionary_identity
        .terrane_v1_digest()
        .expect("dictionary digest");
    let plaintext = b"dictionary dependency vocabulary extended words payload\n".repeat(128);
    let content_identity = store_chunk(&store, &plaintext, Some(&dictionary));
    let fixture_object = Object::new(plaintext);
    let (commit, history, location, secret) = fixture(&fixture_object);
    let verifier = Checked {
        history: &history,
        location: &location,
    };
    let dictionaries = StoreDictionaries::new(&store, &profile);
    let object = ready(StoreObject::open(
        &store,
        &dictionaries,
        &profile,
        ContentRef::Inline(content_identity.terrane_v1_digest().expect("object digest")),
        fixture_object.size(),
    ))
    .expect("actual dictionary-coded object");
    assert_eq!(object.digest(), fixture_object.digest());
    let mut table = SideTable::new();
    let records = ready(produce_required_signed(
        &mut table,
        &store,
        &object,
        &Requirements {
            hashes: Vec::new(),
            classify: vec![Magic::Text],
        },
        &SignedProducer::new(&commit, &secret),
        &verifier,
        true,
    ))
    .expect("signed classification from verified stored plaintext");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.value, AttributeValue::Magic(Magic::Text));
    let identity = record.identity().expect("signed record identity");
    let quarantine = RecordingQuarantine::default();

    // Keep a valid frame but replace its dependency with a cycle. The reader
    // fails before exposing plaintext, so the signed value is still unchecked.
    let original = store
        .bytes
        .lock()
        .expect("fixture mutex")
        .get(dictionary_identity.digest())
        .expect("stored dictionary")
        .clone();
    assert_eq!(
        parse_envelope(&original)
            .expect("dictionary envelope")
            .codec,
        Codec::ZstdDictionary(base_identity.terrane_v1_digest().expect("base digest"))
    );
    let mut cyclic = original.clone();
    cyclic[1..33].copy_from_slice(&dictionary_digest);
    store
        .bytes
        .lock()
        .expect("fixture mutex")
        .insert(dictionary_identity.digest().to_vec(), cyclic);

    assert!(matches!(
        ready(table.verify_durable(&identity, &object, &quarantine)),
        Err(Error::Derived(terrane_format::derived::Error::InvalidValue))
    ));
    assert!(table.quarantined().is_empty());
    assert!(
        quarantine
            .identities
            .lock()
            .expect("fixture mutex")
            .is_empty()
    );
    assert_eq!(table.trust(&identity), Some(Trust::VerifiedProducer));
    assert_eq!(
        table.current(object.digest(), AttributeName::Magic, true),
        Some(record)
    );
    assert_eq!(
        table
            .producer_evidence(&identity)
            .expect("retained proof")
            .record(),
        &identity
    );
    assert_eq!(
        ready(store.get(&identity, None)).expect("retained immutable bytes"),
        record.encode().expect("signed record bytes")
    );

    store
        .bytes
        .lock()
        .expect("fixture mutex")
        .insert(dictionary_identity.digest().to_vec(), original);
    ready(table.verify_durable(&identity, &object, &quarantine))
        .expect("restored dependency allows verified retry");
    assert!(table.quarantined().is_empty());
    assert!(
        quarantine
            .identities
            .lock()
            .expect("fixture mutex")
            .is_empty()
    );

    // A fresh attempt must still quarantine a genuine value contradiction,
    // including when its public error is the same as the earlier read failure.
    let mut wrong = AttrRecord::new(
        object.digest(),
        AttributeValue::Magic(Magic::Other),
        commit.identity(),
    );
    wrong
        .sign(&commit, &secret)
        .expect("signed incorrect claim");
    let wrong_identity =
        ready(table.put(&store, wrong, &verifier)).expect("independently attributed claim");
    assert!(matches!(
        ready(table.verify_durable(&wrong_identity, &object, &quarantine)),
        Err(Error::Derived(terrane_format::derived::Error::InvalidValue))
    ));
    assert_eq!(table.quarantined().len(), 1);
    assert_eq!(table.quarantined()[0].identity, wrong_identity);
    assert_eq!(
        *quarantine.identities.lock().expect("fixture mutex"),
        vec![wrong_identity]
    );
    assert_eq!(table.trust(&identity), Some(Trust::VerifiedProducer));
    assert_eq!(
        table.current(object.digest(), AttributeName::Magic, true),
        Some(record)
    );
}
