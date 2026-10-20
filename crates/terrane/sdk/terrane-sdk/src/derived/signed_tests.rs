//! Verifies configured detached signing and checked side-only production.

use super::*;
use terrane_format::{
    auth::{Authority, Grant, IssuerKey, Request, Token, Verb, Verbs},
    provenance::{EntryLocation, VerifiedCommit, VerifiedHistory, sign},
    refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance},
    tree_format::{ContentRef, Entry, EntryKind, LeafItem, Node, NodeItems, encode_node},
};

#[cfg(feature = "tokio")]
#[path = "context_tests.rs"]
mod context_tests;

#[path = "read_failure_tests.rs"]
mod read_failure_tests;

// RFC 8032 test vector 1 is public fixture material, not a configured credential.
fn vector<const N: usize>(hex: &str) -> [u8; N] {
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("fixture hex");
    }
    result
}

fn fixture(object: &Object) -> (VerifiedCommit, VerifiedHistory, EntryLocation, [u8; 32]) {
    let secret = vector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = vector("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: object.size(),
                    content: ContentRef::Inline(object.digest()),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }]),
        props: None,
    };
    let bytes = encode_node(&node, true, 262144).expect("canonical side-only object tree");
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .expect("node identity")
        .terrane_v1_digest()
        .expect("root digest");
    let token = Token::issue(
        Authority {
            issuer: "issuer".to_owned(),
            key_id: "key".to_owned(),
            subject: "producer".to_owned(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".to_owned()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![
                Grant::new(
                    "refs/heads/main".to_owned(),
                    Verbs::new(4).expect("commit bit"),
                )
                .expect("grant"),
            ],
            workload: Some("job".to_owned()),
        },
        &secret,
        public,
    )
    .expect("public fixture token");
    let commit = Commit {
        tree: root,
        parents: Vec::new(),
        provenance: Provenance {
            issuer: "issuer".to_owned(),
            token_id: [3; 16],
            subject: "producer".to_owned(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("job".to_owned()),
            process: "attribute-tests".to_owned(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Derived,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: "Compute side attributes".to_owned(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "default".to_owned(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            commit_context: None,
            entry_receipts: None,
        },
        packs: None,
        signature: None,
    };
    let locality = Locality::default();
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &[],
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    let commit = sign(
        commit,
        &secret,
        &[IssuerKey {
            issuer: "issuer".to_owned(),
            key_id: "key".to_owned(),
            public_key: public,
            retirement: None,
        }],
        &request,
        4,
    )
    .expect("verified producer commit");
    let location = EntryLocation {
        commit: commit.identity(),
        root,
        path: b"file".to_vec(),
    };
    let mut history = VerifiedHistory::new(262144);
    history
        .insert_commit(commit.clone())
        .expect("producer history");
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("reachable canonical tree");
    (commit, history, location, secret)
}

struct Checked<'a> {
    history: &'a VerifiedHistory,
    location: &'a EntryLocation,
}

#[test]
fn bad_detached_signature_is_quarantined_while_valid_producer_is_retained() {
    let object = Object::new(b"plaintext".to_vec());
    let (commit, history, location, secret) = fixture(&object);
    let mut good = AttrRecord::new(
        object.digest(),
        AttributeValue::Magic(Magic::Text),
        commit.identity(),
    );
    good.sign(&commit, &secret)
        .expect("valid detached signature");
    let mut bad = good.clone();
    bad.signature.as_mut().expect("signature")[0] ^= 1;
    let store = MemoryStore::default();
    let mut supplied = SideTable::new();
    let good_id = ready(supplied.put(&store, good.clone(), &Untrusted)).expect("good upload");
    let bad_id = ready(supplied.put(&store, bad, &Untrusted)).expect("untrusted upload");
    let verifier = Checked {
        history: &history,
        location: &location,
    };

    let rebuilt = ready(SideTable::rebuild(
        &store,
        &Catalog(vec![good_id.clone(), bad_id.clone()]),
        &verifier,
    ))
    .expect("conclusive invalid producer is individually quarantined");
    assert_eq!(rebuilt.quarantined().len(), 1);
    assert_eq!(rebuilt.quarantined()[0].identity, bad_id);
    assert_eq!(rebuilt.trust(&good_id), Some(Trust::VerifiedProducer));
    assert_eq!(
        rebuilt.current(object.digest(), AttributeName::Magic, true),
        Some(&good)
    );
}

impl ProducerVerifier for Checked<'_> {
    fn verify(&self, record: &AttrRecord) -> Result<Option<ProducerEvidence>, Error> {
        ProducerEvidence::from_history(record, self.history, self.location).map(Some)
    }
}

#[test]
fn signed_required_side_records_gain_checked_producer_evidence_and_reuse_metadata() {
    let object = Object::new(b"plaintext".to_vec());
    let store = MemoryStore::default();
    let (commit, history, location, secret) = fixture(&object);
    let signer = SignedProducer::new(&commit, &secret);
    let verifier = Checked {
        history: &history,
        location: &location,
    };
    let requirements = Requirements {
        hashes: vec![AttributeName::Sha256],
        classify: vec![Magic::Text],
    };
    let mut table = SideTable::new();
    let records = ready(produce_required_signed(
        &mut table,
        &store,
        &object,
        &requirements,
        &signer,
        &verifier,
        true,
    ))
    .expect("signed required side-only records");
    assert_eq!(records.len(), 2);
    for record in &records {
        assert!(record.signature.is_some());
        let identity = record.identity().expect("identity");
        assert_eq!(table.trust(&identity), Some(Trust::VerifiedProducer));
        let evidence = table
            .producer_evidence(&identity)
            .expect("retained producer proof");
        assert_eq!(evidence.record(), &identity);
        assert_eq!(evidence.object(), &object.digest());
        assert_eq!(evidence.function(), &record.function);
        assert_eq!(evidence.value(), record.value.encode().expect("value"));
        assert_eq!(evidence.location(), &location);
    }
    let reads = object.reads.load(Ordering::Relaxed);
    let cached = ready(produce_required_signed(
        &mut table,
        &store,
        &object,
        &requirements,
        &signer,
        &verifier,
        true,
    ))
    .expect("metadata hits");
    assert_eq!(cached, records);
    assert_eq!(object.reads.load(Ordering::Relaxed), reads);
    let rebuilt = ready(SideTable::rebuild(
        &store,
        &Catalog(
            records
                .iter()
                .map(|record| record.identity().expect("identity"))
                .collect(),
        ),
        &verifier,
    ))
    .expect("checked catalog rebuild");
    assert!(
        rebuilt
            .current(object.digest(), AttributeName::Sha256, true)
            .is_some()
    );
    assert!(records.iter().all(|record| {
        rebuilt
            .producer_evidence(&record.identity().expect("identity"))
            .is_some()
    }));

    let wrong_secret = [0; 32];
    let wrong = SignedProducer::new(&commit, &wrong_secret);
    let mut empty = SideTable::new();
    assert!(
        ready(produce_required_signed(
            &mut empty,
            &store,
            &object,
            &requirements,
            &wrong,
            &verifier,
            true
        ))
        .is_err()
    );
}

#[test]
fn dictionary_selection_requires_checked_class_and_explicit_unique_mapping() {
    let object = Object::new(b"plaintext".to_vec());
    let (commit, history, location, secret) = fixture(&object);
    let mut class = AttrRecord::new(
        object.digest(),
        AttributeValue::Magic(Magic::Text),
        commit.identity(),
    );
    class.sign(&commit, &secret).expect("signed classification");
    let evidence = terrane_format::derived::verify_record_producer(&class, &history, &location)
        .expect("checked class.magic witness");
    let dictionary = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"dictionary")
        .expect("dictionary identity");
    let mapping = DictionarySet::new([(Magic::Text, dictionary.clone())])
        .expect("explicit deployment mapping");
    assert_eq!(
        mapping.select(&evidence).expect("selected dictionary"),
        Some(dictionary.terrane_v1_digest().expect("dictionary digest"))
    );
    assert_eq!(
        DictionarySet::default()
            .select(&evidence)
            .expect("no registered default"),
        None
    );
    assert!(
        DictionarySet::new([
            (Magic::Text, dictionary.clone()),
            (Magic::Text, dictionary.clone())
        ])
        .is_err()
    );
    assert!(
        DictionarySet::new([(Magic::Text, class.identity().expect("record identity"))]).is_err()
    );

    let mut supplied = AttrRecord::new(
        object.digest(),
        AttributeValue::ZstdDictionary(dictionary.terrane_v1_digest().expect("chunk digest")),
        commit.identity(),
    );
    supplied
        .sign(&commit, &secret)
        .expect("signed deployment choice");
    let supplied_evidence =
        terrane_format::derived::verify_record_producer(&supplied, &history, &location)
            .expect("authenticated supplied dictionary metadata");
    assert!(mapping.select(&supplied_evidence).is_err());

    let store = MemoryStore::default();
    let verifier = Checked {
        history: &history,
        location: &location,
    };
    let mut table = SideTable::new();
    let identity = ready(table.put(&store, supplied, &verifier)).expect("retain supplied metadata");
    assert_eq!(table.trust(&identity), Some(Trust::VerifiedProducer));
    assert!(matches!(
        ready(table.verify(&identity, &object)),
        Err(Error::Derived(
            terrane_format::derived::Error::UnsupportedFunction
        ))
    ));
    assert!(table.quarantined().is_empty());
    assert_eq!(table.trust(&identity), Some(Trust::VerifiedProducer));
    let reads = object.reads.load(Ordering::Relaxed);
    assert!(matches!(
        ready(compute(&object, &[AttributeName::ZstdDictionary])),
        Err(Error::Derived(
            terrane_format::derived::Error::UnsupportedFunction
        ))
    ));
    assert_eq!(object.reads.load(Ordering::Relaxed), reads);

    trained_class_dictionaries_follow_verified_object_classification();
}

/// Builds disjoint, deterministic training samples for two registered classes.
fn class_training_samples(class: Magic) -> Vec<Vec<u8>> {
    (0..64)
        .map(|sample| {
            let mut bytes = match class {
                Magic::Text => String::from("account,region,quantity,description\n"),
                Magic::Shebang => String::from("#!/bin/tool\n"),
                _ => panic!("only the two explicit fixture classes are trained"),
            };
            for row in 0..32 {
                let line = match class {
                    Magic::Text => format!(
                        "account-{sample:03},region-{},quantity-{},ledger entry {row:03}\n",
                        sample % 7,
                        row * 13 + sample,
                    ),
                    Magic::Shebang => format!(
                        "export ITEM_{row:03}=value_{sample:03}\nrun_task --stage {} --item {row:03}\n",
                        sample % 11,
                    ),
                    _ => unreachable!("class checked before assembling rows"),
                };
                bytes.push_str(&line);
            }
            bytes.into_bytes()
        })
        .collect()
}

/// Constructs the expected chunk address directly from its registered preimage.
fn expected_dictionary_identity(plaintext: &[u8]) -> Identity {
    let mut preimage = blake3::Hasher::new();
    preimage.update(b"terrane-chunk-v1\0");
    preimage.update(plaintext);
    TERRANE_V1
        .from_digest(IdentityKind::Chunk, preimage.finalize().as_bytes())
        .expect("independent chunk-domain digest")
}

/// Couples real training and authenticated classification to ordinary chunk reads.
fn trained_class_dictionaries_follow_verified_object_classification() {
    let classes = [Magic::Text, Magic::Shebang];
    let corpora = classes.map(class_training_samples);
    let dictionaries = corpora.each_ref().map(|samples| {
        zstd::dict::from_samples(samples, 2048).expect("actual per-class dictionary training")
    });
    assert_ne!(dictionaries[0], dictionaries[1]);
    let identities = dictionaries
        .each_ref()
        .map(|bytes| expected_dictionary_identity(bytes));
    assert_ne!(identities[0], identities[1]);
    let mapping = DictionarySet::new([
        (Magic::Text, identities[0].clone()),
        (Magic::Shebang, identities[1].clone()),
    ])
    .expect("distinct trained deployment dictionaries");
    let store = MemoryStore::default();
    let profile = terrane_format::chunking::ChunkProfile::cdc_1m([0; 32]);

    // These private test insertions retain real codec envelopes. The production
    // resolver still fetches and verifies dictionary plaintext by its identity.
    for (dictionary, identity) in dictionaries.iter().zip(&identities) {
        let encoded = crate::codec::encode_chunk(dictionary, profile.maximum(), 3, None)
            .expect("standalone final dictionary encoding");
        store
            .bytes
            .lock()
            .expect("test mutex")
            .insert(identity.digest().to_vec(), encoded);
    }
    for (index, class) in classes.into_iter().enumerate() {
        let mut plaintext = corpora[index][0].clone();
        for sample in &corpora[index][1..8] {
            plaintext.extend_from_slice(sample);
        }
        let object = Object::new(plaintext.clone());
        let (commit, history, location, secret) = fixture(&object);
        let verifier = Checked {
            history: &history,
            location: &location,
        };
        let mut table = SideTable::new();
        // Request actual class.magic without the optional shebang detail record.
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
        .expect("class.magic computed from actual object and signed by checked producer");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.value, AttributeValue::Magic(class));
        let record_identity = record.identity().expect("classification record identity");
        assert_eq!(table.trust(&record_identity), Some(Trust::VerifiedProducer));
        ready(table.verify(&record_identity, &object))
            .expect("recomputed plaintext classification");
        assert!(object.max_read.load(Ordering::Relaxed) <= MAGIC_PREFIX_LIMIT);
        let evidence = terrane_format::derived::verify_record_producer(record, &history, &location)
            .expect("authenticated reachable class.magic producer");

        let reads = object.reads.load(Ordering::Relaxed);
        let selected = mapping
            .select(&evidence)
            .expect("checked per-class choice")
            .expect("explicit class dictionary");
        assert_eq!(
            selected,
            identities[index]
                .terrane_v1_digest()
                .expect("expected digest")
        );
        assert_ne!(
            selected,
            identities[1 - index]
                .terrane_v1_digest()
                .expect("other class digest")
        );
        assert_eq!(object.reads.load(Ordering::Relaxed), reads);
        assert_ne!(record_identity.kind(), identities[index].kind());

        let resolver = StoreDictionaries::new(&store, &profile);
        let dictionary_reads = store.reads.load(Ordering::Relaxed);
        let dictionary =
            ready(resolver.resolve(selected)).expect("fetched and verified trained dictionary");
        assert_eq!(dictionary, dictionaries[index]);
        assert_eq!(store.reads.load(Ordering::Relaxed), dictionary_reads + 1);
        let encoded =
            crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, Some(&dictionary))
                .expect("selected trained dictionary encodes actual class object");
        assert_eq!(
            terrane_format::codec::parse_envelope(&encoded)
                .expect("dictionary envelope")
                .codec,
            terrane_format::codec::Codec::ZstdDictionary(selected),
        );
        let identity = expected_dictionary_identity(&plaintext);
        store
            .bytes
            .lock()
            .expect("test mutex")
            .insert(identity.digest().to_vec(), encoded.clone());
        let fetched = ready(store.get(&identity, None)).expect("stored dictionary-coded chunk");
        assert_eq!(fetched, encoded);
        let decoded = crate::codec::decode_verified(
            &fetched,
            plaintext.len(),
            &profile,
            true,
            &identity,
            Some(&dictionary),
        )
        .expect("dictionary-coded plaintext and chunk identity verified");
        assert_eq!(decoded.plaintext(), plaintext);
        assert_eq!(decoded.identity(), &identity);
    }
}
