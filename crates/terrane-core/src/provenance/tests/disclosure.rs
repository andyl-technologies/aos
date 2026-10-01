//! Exercises genuine scoped authorities and destination-only disclosure histories.

use super::*;
use crate::{
    auth::RequestRoot,
    cbor,
    identity::Digest,
    properties::Defaults,
    refs::{CommitContext, DisclosureProof, EntryOrigin, EntrySource},
    tree_format::{Attribute, ContentRef, Entry, EntryKind, Property},
};

const SOURCE_DOMAIN: &str = "private:source";
const PUBLIC: &str = "public";
const AUTHORITY_SECRET: [u8; 32] = [21; 32];

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "test",
        private_domain: SOURCE_DOMAIN,
        home: "west",
    }
}

fn authority() -> DisclosureAuthority<'static> {
    DisclosureAuthority {
        repository: "private-source-repository",
        domain: SOURCE_DOMAIN,
        public_key: SigningKey::from_bytes(&AUTHORITY_SECRET)
            .verifying_key()
            .to_bytes(),
        not_before: 50,
        not_after: Some(150),
    }
}

fn root_tree(items: Vec<crate::tree_format::LeafItem<'_>>, domain: &str) -> (Digest, Vec<u8>) {
    let mut value = Vec::new();
    cbor::write_text(&mut value, domain);
    tree(
        items,
        Some(vec![
            Property {
                name: "domain",
                value: &value,
            },
            Property {
                name: "trust",
                value: b"\x63any",
            },
        ]),
    )
}

fn authored(commit: Commit, domain: &str, secret: &[u8; 32], baseline: bool) -> VerifiedCommit {
    authored_claims(
        commit,
        &[RequestRoot { path: b"/", domain }],
        secret,
        baseline,
    )
}

fn authored_claims(
    mut commit: Commit,
    roots: &[RequestRoot<'_>],
    secret: &[u8; 32],
    baseline: bool,
) -> VerifiedCommit {
    let old = Token::decode(commit.provenance.embedded_token.as_deref().unwrap()).unwrap();
    let mut authorization = old.verify(&issuer_keys(), 100).unwrap().authority().clone();
    if !baseline {
        authorization.groups.clear();
        authorization.subject = "build/public".to_string();
    }
    let token = Token::issue(
        authorization,
        &[7; 32],
        SigningKey::from_bytes(secret).verifying_key().to_bytes(),
    )
    .unwrap();
    commit.provenance.subject = token
        .verify(&issuer_keys(), 100)
        .unwrap()
        .authority()
        .subject
        .clone();
    commit.provenance.embedded_token = Some(token.encode());
    with_request(|request| {
        let request = Request { roots, ..*request };
        commit.profile_pair.commit_context = Some(CommitContext::from_request(&request).unwrap());
        sign_authored(commit, secret, &issuer_keys(), &request, 4).unwrap()
    })
}

fn file() -> Entry<'static> {
    let mut value = entry(b"");
    value.kind = EntryKind::File {
        mode: 0o644,
        size: 3,
        content: ContentRef::Inline([31; 32]),
        link_id: None,
    };
    value
}

struct Fixture {
    source: VerifiedHistory,
    source_commit: VerifiedCommit,
    destination: VerifiedHistory,
    destination_commit: VerifiedCommit,
    target: EntryLocation,
    source_root: Digest,
    source_bytes: Vec<u8>,
}

fn fixture(value: Entry<'_>) -> Fixture {
    let (source_root, source_bytes) = root_tree(
        vec![
            item(b"file", value.clone()),
            item(b"secret", entry(b"private sibling")),
        ],
        SOURCE_DOMAIN,
    );
    let mut source_commit = unsigned_commit();
    source_commit.tree = source_root;
    let mut sibling_receipt = receipt(source_root, EntryOrigin::Current);
    sibling_receipt.path = b"secret".to_vec();
    source_commit.profile_pair.entry_receipts = Some(vec![
        receipt(source_root, EntryOrigin::Current),
        sibling_receipt,
    ]);
    let source_commit = authored(source_commit, SOURCE_DOMAIN, &[9; 32], true);
    let mut source = VerifiedHistory::new(MIN_CHUNK);
    source
        .insert_tree(source_root, &[(source_root, source_bytes.clone())])
        .unwrap();
    source.insert_commit(source_commit.clone()).unwrap();
    verify_fixture_scope(&mut source, source_commit.identity(), defaults()).unwrap();

    let mut original = Vec::new();
    cbor::write_bytes(&mut original, &source_commit.identity());
    let mut disclosed = value;
    disclosed.attrs.push(Attribute {
        name: "provenance.reintroduced-from",
        value: &original,
    });
    disclosed.attrs_present = true;
    let (root, bytes) = root_tree(vec![item(b"file", disclosed)], PUBLIC);
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![source_commit.identity()];
    let mut certificate_receipt = receipt(root, EntryOrigin::Current);
    certificate_receipt.reintroduced_from = Some(EntrySource {
        commit: source_commit.identity(),
        root: source_root,
        path: b"file".to_vec(),
    });
    certificate_receipt.attributes = Some(vec![(
        "provenance.reintroduced-from".to_string(),
        EntryOrigin::Current,
    )]);
    certificate_receipt.disclosure_proof = Some(DisclosureProof {
        authority_key: super::super::disclosure::key_name(&authority().public_key),
        source_domain: SOURCE_DOMAIN.to_string(),
        observed_at: 100,
        signature: [0; 64],
    });
    commit.profile_pair.entry_receipts = Some(vec![certificate_receipt]);
    let prototype = authored(commit, PUBLIC, &[11; 32], false);
    let mut destination = VerifiedHistory::new(MIN_CHUNK);
    destination
        .insert_tree(root, &[(root, bytes.clone())])
        .unwrap();
    destination.insert_commit(prototype.clone()).unwrap();
    let signature = sign_disclosure(
        DisclosureSigning {
            source_history: &source,
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
    .unwrap();
    let mut final_commit = prototype.commit().clone();
    final_commit.profile_pair.entry_receipts.as_mut().unwrap()[0]
        .disclosure_proof
        .as_mut()
        .unwrap()
        .signature = signature;
    let destination_commit = authored(final_commit, PUBLIC, &[11; 32], false);
    destination = VerifiedHistory::new(MIN_CHUNK);
    // No private commit, source tree, sibling metadata or source token is copied.
    destination.insert_tree(root, &[(root, bytes)]).unwrap();
    destination
        .insert_commit(destination_commit.clone())
        .unwrap();
    let target = EntryLocation {
        commit: destination_commit.identity(),
        root,
        path: b"file".to_vec(),
    };
    Fixture {
        source,
        source_commit,
        destination,
        destination_commit,
        target,
        source_root,
        source_bytes,
    }
}

fn changed_destination(fixture: &Fixture, commit: Commit) -> (VerifiedHistory, VerifiedCommit) {
    let signed = authored(commit, PUBLIC, &[11; 32], false);
    let mut history = fixture.destination.clone();
    history.insert_commit(signed.clone()).unwrap();
    (history, signed)
}

fn resign_certificate(
    fixture: &Fixture,
    mut commit: Commit,
    history: &VerifiedHistory,
) -> VerifiedCommit {
    let prototype = authored(commit.clone(), PUBLIC, &[11; 32], false);
    let mut history = history.clone();
    history.insert_commit(prototype.clone()).unwrap();
    let signature = sign_disclosure(
        DisclosureSigning {
            source_history: &fixture.source,
            source_commit: fixture.source_commit.identity(),
            source_path: b"file",
            destination_history: &history,
            destination_commit: prototype.identity(),
            destination_path: b"file",
            source_defaults: defaults(),
            destination_defaults: defaults(),
        },
        authority(),
        &AUTHORITY_SECRET,
    )
    .unwrap();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|receipt| receipt.path == b"file")
        .unwrap()
        .disclosure_proof
        .as_mut()
        .unwrap()
        .signature = signature;
    authored(commit, PUBLIC, &[11; 32], false)
}

fn disclosed_candidate<'a>(
    history: &VerifiedHistory,
    view: Digest,
    authorities: &[DisclosureAuthority<'_>],
    defaults: Defaults<'a>,
) -> Result<DisclosureCandidate<'a>, Rejected> {
    DisclosureCandidate::new_with_bootstrap(
        history,
        view,
        authorities,
        defaults,
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )
}

mod boundaries;
mod projection;
mod retention;
