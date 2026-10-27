//! Exercises producer authority only after complete disclosure and root checks.

use super::*;
use crate::{
    auth::{Request, RequestRoot, Verb},
    cbor,
    identity::{Digest, IdentityKind, TERRANE_V1},
    properties::Defaults,
    provenance::{
        DisclosureAuthority, DisclosureCandidate, DisclosureSigning, EntryLocation,
        OriginalBootstrapPolicy, VerifiedCommit, VerifiedHistory, derive_fresh_roots,
        sign_authored, sign_disclosure, verify_root_context, verify_root_context_with_bootstrap,
    },
    refs::{
        Commit, CommitContext, DisclosureProof, EntryOrigin, EntryReceipt, EntrySource, Locality,
    },
    tree_format::{
        Attribute, ContentRef, Entry, EntryKind, LeafItem, Node, NodeItems, Property, encode_node,
    },
};
use alloc::{string::ToString, vec, vec::Vec};
use ed25519_dalek::SigningKey;

const MIN_CHUNK: u64 = 262144;
const SOURCE_DOMAIN: &str = "private:source";
const PUBLIC_DOMAIN: &str = "public";
const PRODUCER_SECRET: [u8; 32] = [9; 32];
const AUTHORITY_SECRET: [u8; 32] = [21; 32];

// Independently retained physical configuration is separate from signed trees,
// token issuers, and the current ACL. These original fixture ACLs were empty.
const SOURCE_PHYSICAL_AUTHORITY: &str = "fixture-original-source-authority";
const DESTINATION_PHYSICAL_AUTHORITY: &str = "fixture-original-destination-authority";
const SOURCE_BOOTSTRAP: OriginalBootstrapPolicy<'static> = OriginalBootstrapPolicy {
    authority: "fixture-original-source-authority",
    reference: "refs/heads/main",
    writer_epoch: 4,
    acl: &[],
};
const DESTINATION_BOOTSTRAP: OriginalBootstrapPolicy<'static> = OriginalBootstrapPolicy {
    authority: "fixture-original-destination-authority",
    reference: "refs/heads/main",
    writer_epoch: 4,
    acl: &[],
};

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "test",
        private_domain: SOURCE_DOMAIN,
        home: "west",
    }
}

fn authority() -> DisclosureAuthority<'static> {
    DisclosureAuthority {
        repository: "source-repository",
        domain: SOURCE_DOMAIN,
        public_key: SigningKey::from_bytes(&AUTHORITY_SECRET)
            .verifying_key()
            .to_bytes(),
        not_before: 50,
        not_after: Some(150),
    }
}

fn root_tree(domain: &str, original: Option<Digest>) -> (Digest, Vec<u8>) {
    let mut domain_value = Vec::new();
    cbor::write_text(&mut domain_value, domain);
    let mut original_value = Vec::new();
    if let Some(original) = original {
        cbor::write_bytes(&mut original_value, &original);
    }

    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: 3,
                    content: ContentRef::Inline([7; 32]),
                    link_id: None,
                },
                attrs: if original.is_some() {
                    vec![Attribute {
                        name: "provenance.reintroduced-from",
                        value: &original_value,
                    }]
                } else {
                    Vec::new()
                },
                attrs_present: original.is_some(),
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }]),
        props: Some(vec![
            Property {
                name: "domain",
                value: &domain_value,
            },
            Property {
                name: "trust",
                value: b"\x63any",
            },
        ]),
    };
    let bytes = encode_node(&node, true, MIN_CHUNK).expect("canonical root tree");
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .expect("node identity")
        .terrane_v1_digest()
        .expect("node digest");
    (root, bytes)
}

fn receipt(root: Digest) -> EntryReceipt {
    EntryReceipt {
        root,
        path: b"file".to_vec(),
        origin: EntryOrigin::Current,
        attributes: None,
        reintroduced_from: None,
        disclosure_proof: None,
    }
}

fn authored(mut commit: Commit, domain: &str) -> VerifiedCommit {
    let locality = Locality::default();
    let roots = [RequestRoot { path: b"/", domain }];
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &roots,
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    commit.profile_pair.commit_context =
        Some(CommitContext::from_request(&request).expect("original root claims"));
    commit.signature = None;
    sign_authored(commit, &PRODUCER_SECRET, &keys(), &request, 4)
        .expect("genuine original-context signature")
}

fn history(commit: &VerifiedCommit, root: Digest, bytes: Vec<u8>) -> VerifiedHistory {
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_commit(commit.clone())
        .expect("signed commit");
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("canonical root witness");
    history
}

fn signed_record(commit: &VerifiedCommit) -> AttrRecord {
    let mut record = AttrRecord::new(
        [7; 32],
        AttributeValue::Magic(Magic::Text),
        commit.identity(),
    );
    record
        .sign(commit, &PRODUCER_SECRET)
        .expect("genuine detached terminal-key signature");
    record
}

struct Fixture {
    history: VerifiedHistory,
    producer: VerifiedCommit,
    location: EntryLocation,
}

fn disclosure_fixture() -> Fixture {
    let (source_root, source_bytes) = root_tree(SOURCE_DOMAIN, None);
    let mut source_commit = signed(source_root, Vec::new(), false).commit().clone();
    source_commit.profile_pair.entry_receipts = Some(vec![receipt(source_root)]);
    let source_commit = authored(source_commit, SOURCE_DOMAIN);
    let mut source_history = history(&source_commit, source_root, source_bytes);
    verify_root_context_with_bootstrap(
        &mut source_history,
        source_commit.identity(),
        defaults(),
        SOURCE_PHYSICAL_AUTHORITY,
        SOURCE_BOOTSTRAP,
    )
    .expect("source actual-root authorization with independently retained original policy");

    let (root, bytes) = root_tree(PUBLIC_DOMAIN, Some(source_commit.identity()));
    let mut target_receipt = receipt(root);
    target_receipt.reintroduced_from = Some(EntrySource {
        commit: source_commit.identity(),
        root: source_root,
        path: b"file".to_vec(),
    });
    target_receipt.attributes = Some(vec![(
        "provenance.reintroduced-from".to_string(),
        EntryOrigin::Current,
    )]);
    let authority_key = authority()
        .public_key
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect();
    target_receipt.disclosure_proof = Some(DisclosureProof {
        authority_key,
        source_domain: SOURCE_DOMAIN.to_string(),
        observed_at: 100,
        signature: [0; 64],
    });
    let mut target = signed(root, vec![source_commit.identity()], false)
        .commit()
        .clone();
    target.profile_pair.entry_receipts = Some(vec![target_receipt]);
    let prototype = authored(target, PUBLIC_DOMAIN);
    let destination = history(&prototype, root, bytes.clone());
    let signature = sign_disclosure(
        DisclosureSigning {
            source_history: &source_history,
            source_commit: source_commit.identity(),
            source_path: b"file",
            destination_history: &destination,
            destination_commit: prototype.identity(),
            destination_path: b"file",
            source_defaults: defaults(),
            destination_defaults: defaults(),
        },
        authority(),
        &AUTHORITY_SECRET,
    )
    .expect("actual source authority signs canonical disclosure projection");
    let mut final_commit = prototype.commit().clone();
    final_commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .expect("receipts")[0]
        .disclosure_proof
        .as_mut()
        .expect("proof")
        .signature = signature;
    let producer = authored(final_commit, PUBLIC_DOMAIN);
    let location = EntryLocation {
        commit: producer.identity(),
        root,
        path: b"file".to_vec(),
    };

    Fixture {
        // Reopening copies no private source commit or source witness.
        history: history(&producer, root, bytes),
        producer,
        location,
    }
}

#[test]
fn signed_disclosure_producer_requires_completed_batch_before_typed_evidence() {
    let fixture = disclosure_fixture();
    let record = signed_record(&fixture.producer);
    record
        .verify_signature(&fixture.producer.signing_public_key())
        .expect("valid detached signature alone");
    assert_eq!(
        verify_record_producer(&record, &fixture.history, &fixture.location),
        Err(Error::UnverifiedContext)
    );

    assert!(
        DisclosureCandidate::new(
            &fixture.history,
            fixture.producer.identity(),
            &[authority()],
            defaults(),
        )
        .expect("certificate validation does not invent bootstrap evidence")
        .finish()
        .is_err()
    );
    let (checked, batch) = DisclosureCandidate::new_with_bootstrap(
        &fixture.history,
        fixture.producer.identity(),
        &[authority()],
        defaults(),
        DESTINATION_PHYSICAL_AUTHORITY,
        DESTINATION_BOOTSTRAP,
    )
    .expect("valid canonical certificate candidate")
    .finish()
    .expect("all disclosure origins and actual-root authorization complete");
    let evidence = verify_record_producer(&record, &checked, &fixture.location)
        .expect("completed legitimate producer");
    assert_eq!(batch.boundaries().len(), 1);
    assert_eq!(evidence.record(), &record.identity().expect("identity"));
    assert_eq!(evidence.producer(), &fixture.producer.identity());
    assert_eq!(evidence.location(), &fixture.location);
}

#[test]
fn invalid_disclosure_certificate_cannot_gain_authority_from_valid_record_signature() {
    let mut fixture = disclosure_fixture();
    let mut changed = fixture.producer.commit().clone();
    changed
        .profile_pair
        .entry_receipts
        .as_mut()
        .expect("receipts")[0]
        .disclosure_proof
        .as_mut()
        .expect("proof")
        .signature[0] ^= 1;
    let producer = authored(changed, PUBLIC_DOMAIN);
    fixture
        .history
        .insert_commit(producer.clone())
        .expect("terminal signature authenticates even the invalid certificate bytes");
    fixture.location.commit = producer.identity();
    let record = signed_record(&producer);
    record
        .verify_signature(&producer.signing_public_key())
        .expect("valid detached signature on changed producer");

    assert!(
        DisclosureCandidate::new_with_bootstrap(
            &fixture.history,
            producer.identity(),
            &[authority()],
            defaults(),
            DESTINATION_PHYSICAL_AUTHORITY,
            DESTINATION_BOOTSTRAP,
        )
        .is_err()
    );
    assert_eq!(
        verify_record_producer(&record, &fixture.history, &fixture.location),
        Err(Error::UnverifiedContext)
    );
}

#[test]
fn signed_non_disclosure_producer_requires_actual_root_scope_completion() {
    let (root, bytes) = root_tree(SOURCE_DOMAIN, None);
    let mut commit = signed(root, Vec::new(), false).commit().clone();
    commit.profile_pair.entry_receipts = Some(vec![receipt(root)]);
    let producer = authored(commit.clone(), SOURCE_DOMAIN);
    let mut history = history(&producer, root, bytes);
    let location = EntryLocation {
        commit: producer.identity(),
        root,
        path: b"file".to_vec(),
    };
    let record = signed_record(&producer);
    assert_eq!(
        verify_record_producer(&record, &history, &location),
        Err(Error::UnverifiedContext)
    );

    assert!(verify_root_context(&mut history, producer.identity(), defaults()).is_err());
    assert!(
        verify_root_context_with_bootstrap(
            &mut history,
            producer.identity(),
            defaults(),
            DESTINATION_PHYSICAL_AUTHORITY,
            SOURCE_BOOTSTRAP,
        )
        .is_err()
    );
    assert_eq!(
        verify_record_producer(&record, &history, &location),
        Err(Error::UnverifiedContext)
    );

    verify_root_context_with_bootstrap(
        &mut history,
        producer.identity(),
        defaults(),
        SOURCE_PHYSICAL_AUTHORITY,
        SOURCE_BOOTSTRAP,
    )
    .expect("original authenticated root claims match canonical root");
    assert!(verify_record_producer(&record, &history, &location).is_ok());

    let mislabeled = authored(commit, PUBLIC_DOMAIN);
    history
        .insert_commit(mislabeled.clone())
        .expect("signature authenticates original claims before canonical scope validation");
    assert!(
        verify_root_context_with_bootstrap(
            &mut history,
            mislabeled.identity(),
            defaults(),
            SOURCE_PHYSICAL_AUTHORITY,
            SOURCE_BOOTSTRAP,
        )
        .is_err()
    );
    let invalid_location = EntryLocation {
        commit: mislabeled.identity(),
        ..location
    };
    assert_eq!(
        verify_record_producer(&signed_record(&mislabeled), &history, &invalid_location),
        Err(Error::UnverifiedContext)
    );
}

#[test]
fn legacy_inline_carrying_view_does_not_bypass_actual_producer_context() {
    let value = AttributeValue::Magic(Magic::Text);
    let (root, bytes) = tree(&value);
    let legacy = signed(root, Vec::new(), true);
    let mut history = history(&legacy, root, bytes);
    let roots = derive_fresh_roots(&history, legacy.commit(), defaults())
        .expect("derive the actual implicit root owner without authorizing it");
    let domain = roots
        .affected()
        .iter()
        .find(|root| root.path() == b"/")
        .expect("view root")
        .domain();
    let producer = authored(legacy.commit().clone(), domain);
    let carrying = signed(root, vec![producer.identity()], false);
    history
        .insert_commit(producer.clone())
        .expect("original-context producer");
    history
        .insert_commit(carrying.clone())
        .expect("legacy carrying view");
    let location = EntryLocation {
        commit: carrying.identity(),
        root,
        path: b"file".to_vec(),
    };
    let record = AttrRecord::new([7; 32], value, producer.identity());

    assert_eq!(
        verify_record_producer(&record, &history, &location),
        Err(Error::UnverifiedContext)
    );
    verify_root_context_with_bootstrap(
        &mut history,
        producer.identity(),
        defaults(),
        SOURCE_PHYSICAL_AUTHORITY,
        SOURCE_BOOTSTRAP,
    )
    .expect("actual producer root scope completes independently");
    let evidence = verify_record_producer(&record, &history, &location)
        .expect("legacy inline origin and both view contexts verify");
    assert_eq!(evidence.producer(), &producer.identity());
    assert_eq!(evidence.location(), &location);
}
