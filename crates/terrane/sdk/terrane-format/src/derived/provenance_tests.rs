//! Tests producer attribution with actual signed commits and canonical witnesses.

use super::*;
use crate::{
    auth::{Authority, Grant, IssuerKey, Request, Token, Verb, Verbs},
    identity::{Digest, IdentityKind, TERRANE_V1},
    provenance::{EntryLocation, VerifiedCommit, VerifiedHistory, sign},
    refs::{
        Commit, CommitSource, EntryOrigin, EntryReceipt, Locality, PrincipalKind, ProfilePair,
        Provenance,
    },
    tree_format::{
        Attribute, ContentRef, Entry, EntryKind, LeafItem, Node, NodeItems, encode_node,
    },
};
use alloc::{string::ToString, vec, vec::Vec};
use ed25519_dalek::SigningKey;

const MIN_CHUNK: u64 = 262144;

#[path = "disclosure_tests.rs"]
mod disclosure_tests;

fn keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "issuer".to_string(),
        key_id: "key".to_string(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        retirement: None,
    }]
}

fn tree(value: &AttributeValue) -> (Digest, Vec<u8>) {
    tree_with_inline(value, true)
}

fn tree_with_inline(value: &AttributeValue, inline: bool) -> (Digest, Vec<u8>) {
    let encoded_value = value.encode().expect("canonical inline value");
    let entry = Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 3,
            content: ContentRef::Inline([7; 32]),
            link_id: None,
        },
        attrs: if inline {
            vec![Attribute {
                name: value.name().as_str(),
                value: &encoded_value,
            }]
        } else {
            Vec::new()
        },
        attrs_present: inline,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"file".to_vec(),
            entry,
        }]),
        props: None,
    };
    let bytes = encode_node(&node, true, MIN_CHUNK).expect("canonical tree");
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .expect("node identity")
        .terrane_v1_digest()
        .expect("digest");
    (root, bytes)
}

#[test]
fn detached_signature_binds_all_fields_and_requires_producer_object_witness() {
    let value = AttributeValue::Magic(Magic::Text);
    let (root, bytes) = tree_with_inline(&value, false);
    let producer = signed(root, Vec::new(), false);
    let mut record = AttrRecord::new([7; 32], value, producer.identity());
    let unsigned = record.clone();
    record
        .sign(&producer, &[9; 32])
        .expect("authenticated terminal secret");
    let encoded = record.encode().expect("signed record");
    assert_eq!(AttrRecord::decode(&encoded), Ok(record.clone()));
    assert_ne!(record.identity(), unsigned.identity());
    let mut expected = b"terrane-attr-signature-v1\0".to_vec();
    expected.extend_from_slice(&unsigned.encode().expect("legacy five-field fixture"));
    assert_eq!(record.signature_preimage().expect("preimage"), expected);
    record
        .verify_signature(&producer.signing_public_key())
        .expect("signature");
    assert!(record.sign(&producer, &[8; 32]).is_err());

    let mut history = VerifiedHistory::new(MIN_CHUNK);
    let location = EntryLocation {
        commit: producer.identity(),
        root,
        path: b"file".to_vec(),
    };
    history.insert_commit(producer).expect("verified producer");
    assert!(verify_record_producer(&record, &history, &location).is_err());
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("canonical producer tree");
    let evidence =
        verify_record_producer(&record, &history, &location).expect("side-only attribution");
    assert_eq!(
        evidence.record(),
        &record.identity().expect("record identity")
    );
    assert_eq!(evidence.location(), &location);
    assert!(verify_record_producer(&unsigned, &history, &location).is_err());

    let mut changed = record.clone();
    changed.object = [8; 32];
    assert!(changed.verify_signature(&[0; 32]).is_err());
    assert!(verify_record_producer(&changed, &history, &location).is_err());
    changed = record.clone();
    changed.value = AttributeValue::Magic(Magic::Other);
    assert!(verify_record_producer(&changed, &history, &location).is_err());
    changed.value = AttributeValue::Sha256([0; 32]);
    changed.function = AttributeName::Sha256.function();
    assert!(verify_record_producer(&changed, &history, &location).is_err());
    changed = record.clone();
    changed.function.version = "2".to_string();
    assert_eq!(
        verify_record_producer(&changed, &history, &location),
        Err(Error::UnsupportedFunction)
    );
    changed = record.clone();
    changed.producer = [8; 32];
    assert!(verify_record_producer(&changed, &history, &location).is_err());
    let mut bad_signature = record;
    bad_signature.signature.as_mut().expect("signature")[0] ^= 1;
    assert!(verify_record_producer(&bad_signature, &history, &location).is_err());
}

fn signed(root: Digest, parents: Vec<Digest>, new_attribute: bool) -> VerifiedCommit {
    let token = Token::issue(
        Authority {
            issuer: "issuer".to_string(),
            key_id: "key".to_string(),
            subject: "producer".to_string(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".to_string()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![
                Grant::new(
                    "refs/heads/main".to_string(),
                    Verbs::new(4).expect("commit bit"),
                )
                .expect("grant"),
            ],
            workload: Some("job".to_string()),
        },
        &[7; 32],
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .expect("signed capability");
    let commit = Commit {
        tree: root,
        parents,
        provenance: Provenance {
            issuer: "issuer".to_string(),
            token_id: [3; 16],
            subject: "producer".to_string(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("job".to_string()),
            process: "attribute-tests".to_string(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Derived,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: "Compute attributes".to_string(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "default".to_string(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            commit_context: None,
            entry_receipts: if new_attribute {
                Some(vec![EntryReceipt {
                    root,
                    path: b"file".to_vec(),
                    origin: EntryOrigin::Current,
                    attributes: Some(vec![("class.magic".to_string(), EntryOrigin::Current)]),
                    reintroduced_from: None,
                    disclosure_proof: None,
                }])
            } else {
                None
            },
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
    sign(commit, &[9; 32], &keys(), &request, 4).expect("verified signed commit")
}

#[test]
fn producer_requires_signed_object_value_and_separate_attribute_origin() {
    let value = AttributeValue::Magic(Magic::Text);
    let (root, bytes) = tree(&value);
    let introduced = signed(root, Vec::new(), true);
    let producer = introduced.identity();
    let carried = signed(root, vec![producer], false);
    let view = carried.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_commit(introduced)
        .expect("introducing commit");
    history.insert_commit(carried).expect("carrying commit");
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("tree witness");
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };
    let record = AttrRecord::new([7; 32], value, producer);

    assert_eq!(verify_producer(&record, &history, &location), Ok(()));
    let mut claimed = record.clone();
    claimed.producer = view;
    assert_eq!(
        verify_producer(&claimed, &history, &location),
        Err(Error::InvalidProvenance)
    );
    claimed = record.clone();
    claimed.object = [8; 32];
    assert_eq!(
        verify_producer(&claimed, &history, &location),
        Err(Error::InvalidProvenance)
    );
    claimed = record.clone();
    claimed.value = AttributeValue::Magic(Magic::Other);
    assert_eq!(
        verify_producer(&claimed, &history, &location),
        Err(Error::InlineDisagreement)
    );
    claimed = record;
    claimed.function.version = "2".to_string();
    assert_eq!(
        verify_producer(&claimed, &history, &location),
        Err(Error::UnsupportedFunction)
    );
}

#[test]
fn unrelated_signature_and_unavailable_tree_cannot_authorize_a_record() {
    let value = AttributeValue::Magic(Magic::Text);
    let (root, bytes) = tree(&value);
    let introduced = signed(root, Vec::new(), true);
    let producer = introduced.identity();
    let record = AttrRecord::new([7; 32], value, producer);
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_commit(introduced)
        .expect("verified signature");
    let location = EntryLocation {
        commit: producer,
        root,
        path: b"file".to_vec(),
    };
    assert_eq!(
        verify_producer(&record, &history, &location),
        Err(Error::InvalidProvenance)
    );
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("matching witness");
    assert_eq!(verify_producer(&record, &history, &location), Ok(()));
    let wrong_path = EntryLocation {
        path: b"other".to_vec(),
        ..location.clone()
    };
    assert_eq!(
        verify_producer(&record, &history, &wrong_path),
        Err(Error::InvalidProvenance)
    );
    let wrong_commit = EntryLocation {
        commit: [0; 32],
        ..location
    };
    assert_eq!(
        verify_producer(&record, &history, &wrong_commit),
        Err(Error::UnverifiedContext)
    );
}

#[test]
fn absent_attribute_receipt_does_not_prove_production_in_a_signed_commit() {
    let value = AttributeValue::Magic(Magic::Text);
    let (root, bytes) = tree(&value);
    let signed = signed(root, Vec::new(), false);
    let producer = signed.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_commit(signed)
        .expect("verified signature alone");
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("canonical tree");
    let location = EntryLocation {
        commit: producer,
        root,
        path: b"file".to_vec(),
    };
    let record = AttrRecord::new([7; 32], value, producer);
    assert_eq!(
        verify_producer(&record, &history, &location),
        Err(Error::InvalidProvenance)
    );
}
