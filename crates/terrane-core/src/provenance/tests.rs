//! Exercises commit signatures, closed selectors, and provenance preservation.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::auth::{Authority, Grant, IssuerKey, Request, Token, Verb, Verbs};
use crate::refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance};
use alloc::{string::ToString, vec, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey};

mod context;
mod disclosure;
mod root_context;
mod selector;
mod side_attributes;
mod snapshot;

fn issuer_keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "issuer".to_string(),
        key_id: "issuer-key".to_string(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        retirement: None,
    }]
}

fn unsigned_commit() -> Commit {
    let token = Token::issue(
        Authority {
            issuer: "issuer".to_string(),
            key_id: "issuer-key".to_string(),
            subject: "build/baseline".to_string(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".to_string()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![
                Grant::new("refs/heads/main".to_string(), Verbs::new(4).unwrap()).unwrap(),
            ],
            workload: Some("workload-identity".to_string()),
        },
        &[7; 32],
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();

    Commit {
        tree: [1; 32],
        parents: Vec::new(),
        provenance: Provenance {
            issuer: "issuer".to_string(),
            token_id: [3; 16],
            subject: "build/baseline".to_string(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("workload-identity".to_string()),
            process: "test/sdk".to_string(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Built,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: "build".to_string(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "default".to_string(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: None,
    }
}

fn with_request<T>(action: impl FnOnce(&Request<'_>) -> T) -> T {
    let locality = Locality::default();
    action(&Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &[],
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    })
}

fn fixture_bootstrap() -> OriginalBootstrapPolicy<'static> {
    // This retained fixture configuration is independent of the signed tree.
    OriginalBootstrapPolicy {
        authority: "test-original-physical-authority",
        reference: "refs/heads/main",
        writer_epoch: 4,
        acl: &[],
    }
}

fn verify_fixture_scope(
    history: &mut VerifiedHistory,
    view: crate::identity::Digest,
    defaults: crate::properties::Defaults<'_>,
) -> Result<VerifiedRootScope, Rejected> {
    verify_root_context_with_bootstrap(
        history,
        view,
        defaults,
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )
}

#[test]
fn prov_commit_signature_binds_exact_preimage_and_signed_identity() {
    let unsigned = unsigned_commit();
    let signed =
        with_request(|request| sign(unsigned.clone(), &[9; 32], &issuer_keys(), request, 4))
            .unwrap();
    let preimage = unsigned.signature_preimage().unwrap();
    let expected = SigningKey::from_bytes(&[9; 32]).sign(&preimage).to_bytes();

    assert_eq!(signed.commit().signature, Some(expected));
    assert_eq!(signed.commit().signature_preimage().unwrap(), preimage);
    assert_eq!(signed.identity(), signed.commit().identity().unwrap());
    assert_ne!(signed.identity(), unsigned.identity().unwrap());
    SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .verify_strict(&preimage, &Signature::from_bytes(&expected))
        .unwrap();
}

#[test]
fn prov_commit_verify_rejects_tampering_missing_token_and_wrong_context() {
    let signed =
        with_request(|request| sign(unsigned_commit(), &[9; 32], &issuer_keys(), request, 4))
            .unwrap();
    let mut cases = Vec::new();
    let mut changed = signed.commit().clone();
    changed.parents.push([6; 32]);
    cases.push(("parent", changed));
    let mut changed = signed.commit().clone();
    changed.tree[0] ^= 1;
    cases.push(("tree", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.subject = "other".to_string();
    cases.push(("subject", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.issuer = "other".to_string();
    cases.push(("issuer", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.token_id[0] ^= 1;
    cases.push(("token id", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.kind = PrincipalKind::Human;
    cases.push(("principal kind", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.workload_identity = None;
    cases.push(("workload", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.writer_epoch = 5;
    cases.push(("epoch", changed));
    let mut changed = signed.commit().clone();
    changed.provenance.embedded_token = None;
    cases.push(("missing token", changed));
    let mut changed = signed.commit().clone();
    changed.signature = None;
    cases.push(("missing signature", changed));

    type CommitMutation = (&'static str, fn(&mut Commit));

    let mutations: [CommitMutation; 7] = [
        ("message", |commit| commit.message.push_str("tampered")),
        ("process", |commit| {
            commit.provenance.process.push_str("tampered")
        }),
        ("observed time", |commit| commit.provenance.observed_at += 1),
        ("timestamp", |commit| commit.timestamp += 1),
        ("source", |commit| {
            commit.provenance.source = CommitSource::Imported
        }),
        ("profile", |commit| {
            commit.profile_pair.chunk_profile.push_str("tampered")
        }),
        ("signature", |commit| {
            commit.signature.as_mut().unwrap()[0] ^= 1
        }),
    ];
    for (name, mutate) in mutations {
        let mut changed = signed.commit().clone();
        mutate(&mut changed);
        cases.push((name, changed));
    }

    with_request(|request| {
        assert!(verify(signed.commit(), &issuer_keys(), request, 4).is_ok());
        for (name, changed) in cases {
            assert!(
                verify(&changed, &issuer_keys(), request, 4).is_err(),
                "{name}"
            );
        }
        assert!(verify(signed.commit(), &[], request, 4).is_err());
        assert!(verify(signed.commit(), &issuer_keys(), request, 5).is_err());
        let wrong_ref = Request {
            reference: b"refs/heads/other",
            ..*request
        };
        assert!(verify(signed.commit(), &issuer_keys(), &wrong_ref, 4).is_err());
        assert!(sign(unsigned_commit(), &[8; 32], &issuer_keys(), request, 4).is_err());
    });
}

#[test]
fn prov_commit_signature_uses_last_attenuation_key() {
    let mut commit = unsigned_commit();
    let token = Token::decode(commit.provenance.embedded_token.as_ref().unwrap()).unwrap();
    let attenuated = token
        .attenuate(
            crate::auth::Attenuation::default(),
            &[9; 32],
            SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
    commit.provenance.embedded_token = Some(attenuated.encode());

    with_request(|request| {
        assert!(sign(commit.clone(), &[9; 32], &issuer_keys(), request, 4).is_err());
        let signed = sign(commit, &[10; 32], &issuer_keys(), request, 4).unwrap();
        assert_eq!(
            signed.signing_public_key(),
            SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes()
        );
    });
}

#[test]
fn prov_selector_presets_parse_closed_ast_and_deep_input() {
    for preset in [
        Preset::Any,
        Preset::SignedBaseline,
        Preset::Strict,
        Preset::Attested,
    ] {
        let selector = Selector::preset(preset);
        assert_eq!(Selector::decode(selector.encode()).unwrap(), selector);
    }

    let mut deep = Vec::new();
    for _ in 0..1024 {
        crate::cbor::write_array(&mut deep, 2);
        crate::cbor::write_text(&mut deep, "not");
    }
    deep.extend(Selector::preset(Preset::Any).encode());
    let (history, root, view) = baseline_history();
    let deep_selector = Selector::decode(&deep).unwrap();
    let context = TrustContext::new(&history, view, deep_selector, "private", None).unwrap();
    assert!(context.accepts(root, b"file"));
    for input in [
        b"\x82\x67unknown\x61x".as_slice(),
        b"\x82\x63all\x80",
        b"\x82\x66preset\x61x",
        b"\x82\x68attested\x61x",
    ] {
        assert!(Selector::decode(input).is_err());
    }
}

const MIN_CHUNK: u64 = 1024;

fn entry(target: &'static [u8]) -> crate::tree_format::Entry<'static> {
    crate::tree_format::Entry {
        kind: crate::tree_format::EntryKind::Symlink { target },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn tree(
    entries: Vec<crate::tree_format::LeafItem<'_>>,
    properties: Option<Vec<crate::tree_format::Property<'_>>>,
) -> (crate::identity::Digest, Vec<u8>) {
    let node = crate::tree_format::Node {
        level: 0,
        items: crate::tree_format::NodeItems::Leaf(entries),
        props: properties,
    };
    let bytes = crate::tree_format::encode_node(&node, true, MIN_CHUNK).unwrap();
    let identity = crate::identity::TERRANE_V1
        .calculate(crate::identity::IdentityKind::Node, &bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    (identity, bytes)
}

fn item<'a>(path: &[u8], entry: crate::tree_format::Entry<'a>) -> crate::tree_format::LeafItem<'a> {
    crate::tree_format::LeafItem {
        key: path.to_vec(),
        entry,
    }
}

fn receipt(
    root: crate::identity::Digest,
    origin: crate::refs::EntryOrigin,
) -> crate::refs::EntryReceipt {
    crate::refs::EntryReceipt {
        root,
        path: b"file".to_vec(),
        origin,
        attributes: None,
        reintroduced_from: None,
        disclosure_proof: None,
    }
}

fn signed_record(
    root: crate::identity::Digest,
    parents: Vec<crate::identity::Digest>,
    receipts: Option<Vec<crate::refs::EntryReceipt>>,
    baseline: bool,
) -> VerifiedCommit {
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = parents;
    commit.profile_pair.entry_receipts = receipts.map(|mut receipts| {
        receipts.sort_by(|left, right| (left.root, &left.path).cmp(&(right.root, &right.path)));
        receipts
    });
    if !baseline {
        let old = Token::decode(commit.provenance.embedded_token.as_ref().unwrap()).unwrap();
        let authenticated = old.verify(&issuer_keys(), 100).unwrap();
        let mut authority = authenticated.authority().clone();
        authority.groups.clear();
        authority.subject = "build/untrusted".to_string();
        let token = Token::issue(
            authority,
            &[7; 32],
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        commit.provenance.subject = "build/untrusted".to_string();
        commit.provenance.embedded_token = Some(token.encode());
    }
    with_request(|request| sign(commit, &[9; 32], &issuer_keys(), request, 4)).unwrap()
}

#[test]
fn prov_selector_presets_distinguish_fold_acceptance_from_introduction() {
    let (root, bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let (baseline_root, baseline_bytes) = tree(Vec::new(), None);
    let baseline = signed_record(baseline_root, Vec::new(), None, true);
    let baseline_view = baseline.identity();
    let introduced = signed_record(
        root,
        vec![baseline_view],
        Some(vec![receipt(root, crate::refs::EntryOrigin::Current)]),
        false,
    );
    let introducing = introduced.identity();
    let mut folded = unsigned_commit();
    folded.tree = root;
    folded.parents = vec![baseline_view, introducing];
    folded.provenance.source = CommitSource::Merged;
    let folded =
        with_request(|request| sign(folded, &[9; 32], &issuer_keys(), request, 4)).unwrap();
    let view = folded.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history
        .insert_tree(baseline_root, &[(baseline_root, baseline_bytes)])
        .unwrap();
    history.insert_commit(baseline).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(folded).unwrap();
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };

    assert_eq!(history.introducing_commit(&location), Ok(introducing));
    for (preset, expected) in [
        (Preset::Any, true),
        (Preset::SignedBaseline, true),
        (Preset::Strict, false),
        (Preset::Attested, false),
    ] {
        let context = TrustContext::new(
            &history,
            view,
            Selector::preset(preset),
            "private",
            Some("baseline"),
        )
        .unwrap();
        assert_eq!(context.accepts(root, b"file"), expected, "{preset:?}");
        validate_canonical_context(context.canonical_context()).unwrap();
    }
    assert_eq!(history.provenance_walk(&location).unwrap().len(), 2);
}

#[test]
fn prov_entry_preserve_metadata_and_sources_without_parent_ancestry() {
    let (root, bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let introduced = signed_record(
        root,
        Vec::new(),
        Some(vec![receipt(root, crate::refs::EntryOrigin::Current)]),
        false,
    );
    let introducing = introduced.identity();
    let source = crate::refs::EntrySource {
        commit: introducing,
        root,
        path: b"file".to_vec(),
    };
    let carried = signed_record(
        root,
        Vec::new(),
        Some(vec![receipt(
            root,
            crate::refs::EntryOrigin::Source(source),
        )]),
        true,
    );
    assert_eq!(
        source_commit_references(&carried).collect::<Vec<_>>(),
        vec![introducing]
    );
    let view = carried.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(carried).unwrap();
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };

    assert_eq!(history.introducing_commit(&location), Ok(introducing));
    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::SignedBaseline),
        "private",
        Some("baseline"),
    )
    .unwrap();
    assert!(context.accepts(root, b"file"));
}

#[test]
fn prov_selector_presets_missing_evidence_stays_absent_under_negation() {
    let (root, bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let commit = signed_record(root, Vec::new(), None, true);
    let view = commit.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(commit).unwrap();
    let mut bytes = Vec::new();
    crate::cbor::write_array(&mut bytes, 2);
    crate::cbor::write_text(&mut bytes, "not");
    bytes.extend_from_slice(Selector::preset(Preset::Attested).encode());
    let context = TrustContext::new(
        &history,
        view,
        Selector::decode(&bytes).unwrap(),
        "private",
        None,
    )
    .unwrap();

    assert!(!context.accepts(root, b"file"));
    assert!(!context.accepts(root, b"absent"));
}

#[test]
fn prov_entry_preserve_rejects_unverified_tree_and_invalid_ancestors() {
    let (root, bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    let mut corrupted = bytes.clone();
    corrupted[0] ^= 1;
    assert!(history.insert_tree(root, &[(root, corrupted)]).is_err());
    assert!(
        history
            .insert_tree([1; 32], &[(root, bytes.clone())])
            .is_err()
    );
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let (invalid, bytes) = tree(vec![item(b"missing/child", entry(b"target"))], None);
    assert!(history.insert_tree(invalid, &[(invalid, bytes)]).is_err());
}

#[test]
fn prov_fold_reintroduction_records_verified_original_introduction() {
    let (original_root, original_bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let introduced = signed_record(
        original_root,
        Vec::new(),
        Some(vec![receipt(
            original_root,
            crate::refs::EntryOrigin::Current,
        )]),
        false,
    );
    let introducing = introduced.identity();
    let mut attribute = Vec::new();
    crate::cbor::write_bytes(&mut attribute, &introducing);
    let mut reintroduced_entry = entry(b"target");
    reintroduced_entry.attrs = vec![crate::tree_format::Attribute {
        name: "provenance.reintroduced-from",
        value: &attribute,
    }];
    reintroduced_entry.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", reintroduced_entry)], None);
    let mut reintroduction = receipt(root, crate::refs::EntryOrigin::Current);
    reintroduction.reintroduced_from = Some(crate::refs::EntrySource {
        commit: introducing,
        root: original_root,
        path: b"file".to_vec(),
    });
    for (proof, accepted) in [
        (None, true),
        (
            Some(crate::refs::DisclosureProof {
                authority_key: "ab".repeat(32),
                source_domain: "private:source".to_string(),
                observed_at: 100,
                signature: [0; 64],
            }),
            false,
        ),
    ] {
        let mut candidate = reintroduction.clone();
        candidate.disclosure_proof = proof;
        let commit = signed_record(root, vec![introducing], Some(vec![candidate]), true);
        let view = commit.identity();
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history
            .insert_tree(original_root, &[(original_root, original_bytes.clone())])
            .unwrap();
        history.insert_tree(root, &[(root, bytes.clone())]).unwrap();
        history.insert_commit(introduced.clone()).unwrap();
        history.insert_commit(commit).unwrap();
        let location = EntryLocation {
            commit: view,
            root,
            path: b"file".to_vec(),
        };

        assert_eq!(history.introducing_commit(&location).is_ok(), accepted);
        if accepted {
            assert_eq!(history.introducing_commit(&location), Ok(view));
        }
        let context = TrustContext::new(
            &history,
            view,
            Selector::preset(Preset::Strict),
            "private",
            Some("baseline"),
        );
        assert_eq!(context.is_ok(), accepted);
        if accepted {
            assert!(context.unwrap().accepts(root, b"file"));
        }
    }
}

#[test]
fn prov_selector_presets_root_policy_cannot_be_widened_by_view() {
    let mut strict = Vec::new();
    crate::cbor::write_text(&mut strict, "strict");
    let (root, bytes) = tree(
        vec![item(b"file", entry(b"target"))],
        Some(vec![crate::tree_format::Property {
            name: "trust",
            value: &strict,
        }]),
    );
    let commit = signed_record(
        root,
        Vec::new(),
        Some(vec![receipt(root, crate::refs::EntryOrigin::Current)]),
        false,
    );
    let view = commit.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(commit).unwrap();
    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Any),
        "private",
        Some("baseline"),
    )
    .unwrap();

    assert!(!context.accepts(root, b"file"));
}

#[test]
fn prov_attribute_producer_is_independent_of_content_introduction() {
    let (original_root, original_bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let introduced = signed_record(
        original_root,
        Vec::new(),
        Some(vec![receipt(
            original_root,
            crate::refs::EntryOrigin::Current,
        )]),
        false,
    );
    let introducing = introduced.identity();
    let mut annotated = entry(b"target");
    annotated.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    annotated.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", annotated)], None);
    let source = crate::refs::EntrySource {
        commit: introducing,
        root: original_root,
        path: b"file".to_vec(),
    };
    let mut produced_receipt = receipt(root, crate::refs::EntryOrigin::Source(source));
    produced_receipt.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Current,
    )]);
    let produced = signed_record(root, vec![introducing], Some(vec![produced_receipt]), true);
    let view = produced.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(original_root, &[(original_root, original_bytes)])
        .unwrap();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(produced).unwrap();
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };
    let mut selector = Vec::new();
    crate::cbor::write_array(&mut selector, 3);
    crate::cbor::write_text(&mut selector, "attr-by");
    crate::cbor::write_text(&mut selector, "hash.sha256");
    selector.extend_from_slice(Selector::preset(Preset::Strict).encode());
    let context = TrustContext::new(
        &history,
        view,
        Selector::decode(&selector).unwrap(),
        "private",
        Some("baseline"),
    )
    .unwrap();

    assert_eq!(history.introducing_commit(&location), Ok(introducing));
    assert_eq!(
        history.attribute_producer(&location, "hash.sha256"),
        Ok(view)
    );
    assert!(context.accepts(root, b"file"));
}

#[test]
fn prov_selector_presets_graft_policy_applies_without_subroot_bypass() {
    let mut strict = Vec::new();
    crate::cbor::write_text(&mut strict, "strict");
    let (child_root, child_bytes) = tree(
        vec![item(b"file", entry(b"target"))],
        Some(vec![crate::tree_format::Property {
            name: "trust",
            value: &strict,
        }]),
    );
    let introduced = signed_record(
        child_root,
        Vec::new(),
        Some(vec![receipt(child_root, crate::refs::EntryOrigin::Current)]),
        false,
    );
    let introducing = introduced.identity();
    let mut graft = entry(b"unused");
    graft.kind = crate::tree_format::EntryKind::Tree {
        root: child_root,
        props: None,
    };
    let (root, bytes) = tree(vec![item(b"mount", graft)], None);
    let mut graft_receipt = receipt(root, crate::refs::EntryOrigin::Current);
    graft_receipt.path = b"mount".to_vec();
    let source = crate::refs::EntrySource {
        commit: introducing,
        root: child_root,
        path: b"file".to_vec(),
    };
    let commit = signed_record(
        root,
        Vec::new(),
        Some(vec![
            graft_receipt,
            receipt(child_root, crate::refs::EntryOrigin::Source(source)),
        ]),
        true,
    );
    let view = commit.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(child_root, &[(child_root, child_bytes)])
        .unwrap();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(commit).unwrap();
    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Any),
        "private",
        Some("baseline"),
    )
    .unwrap();

    assert!(!context.accepts_path(b"mount/file"));
    assert!(!context.accepts(child_root, b"file"));
    assert_eq!(context.producer_time(root, b"mount/file"), Some(100));
}

#[test]
fn prov_fold_acceptance_survives_receipt_path_changes() {
    let (original_root, original_bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let introduced = signed_record(
        original_root,
        Vec::new(),
        Some(vec![receipt(
            original_root,
            crate::refs::EntryOrigin::Current,
        )]),
        false,
    );
    let introducing = introduced.identity();
    let accepted = signed_record(original_root, vec![introducing], None, true);
    let accepting = accepted.identity();
    let (root, bytes) = tree(vec![item(b"moved", entry(b"target"))], None);
    let source = crate::refs::EntrySource {
        commit: accepting,
        root: original_root,
        path: b"file".to_vec(),
    };
    let mut moved_receipt = receipt(root, crate::refs::EntryOrigin::Source(source));
    moved_receipt.path = b"moved".to_vec();
    let moved = signed_record(root, vec![accepting], Some(vec![moved_receipt]), false);
    let view = moved.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(original_root, &[(original_root, original_bytes)])
        .unwrap();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(accepted).unwrap();
    history.insert_commit(moved).unwrap();

    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::SignedBaseline),
        "private",
        Some("baseline"),
    )
    .unwrap();
    assert!(context.accepts(root, b"moved"));
    let strict = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Strict),
        "private",
        Some("baseline"),
    )
    .unwrap();
    assert!(!strict.accepts(root, b"moved"));
}

#[test]
fn prov_selector_presets_descendant_baseline_cannot_widen_ancestor_trust() {
    let mut strict = Vec::new();
    let mut any = Vec::new();
    let mut forbidden_group = Vec::new();
    let mut baseline_group = Vec::new();
    crate::cbor::write_text(&mut strict, "strict");
    crate::cbor::write_text(&mut any, "any");
    crate::cbor::write_text(&mut forbidden_group, "forbidden");
    crate::cbor::write_text(&mut baseline_group, "baseline");
    let (child_root, child_bytes) = tree(
        vec![item(b"file", entry(b"target"))],
        Some(vec![
            crate::tree_format::Property {
                name: "trust",
                value: &any,
            },
            crate::tree_format::Property {
                name: "baseline",
                value: &baseline_group,
            },
        ]),
    );
    let introduced = signed_record(
        child_root,
        Vec::new(),
        Some(vec![receipt(child_root, crate::refs::EntryOrigin::Current)]),
        true,
    );
    let introducing = introduced.identity();
    let mut graft = entry(b"unused");
    graft.kind = crate::tree_format::EntryKind::Tree {
        root: child_root,
        props: None,
    };
    let (root, bytes) = tree(
        vec![item(b"mount", graft)],
        Some(vec![
            crate::tree_format::Property {
                name: "trust",
                value: &strict,
            },
            crate::tree_format::Property {
                name: "baseline",
                value: &forbidden_group,
            },
        ]),
    );
    let mut graft_receipt = receipt(root, crate::refs::EntryOrigin::Current);
    graft_receipt.path = b"mount".to_vec();
    let source = crate::refs::EntrySource {
        commit: introducing,
        root: child_root,
        path: b"file".to_vec(),
    };
    let commit = signed_record(
        root,
        Vec::new(),
        Some(vec![
            graft_receipt,
            receipt(child_root, crate::refs::EntryOrigin::Source(source)),
        ]),
        true,
    );
    let view = commit.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(child_root, &[(child_root, child_bytes)])
        .unwrap();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(commit).unwrap();
    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Any),
        "private",
        None,
    )
    .unwrap();

    assert!(!context.accepts_path(b"mount/file"));
    assert!(!context.clone().accepts_path(b"mount/file"));
}

/// Supplies checked baseline evidence to integration tests of the pure algebra.
pub(crate) fn baseline_history() -> (
    VerifiedHistory,
    crate::identity::Digest,
    crate::identity::Digest,
) {
    let (root, bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let commit = signed_record(
        root,
        Vec::new(),
        Some(vec![receipt(root, crate::refs::EntryOrigin::Current)]),
        true,
    );
    let view = commit.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(commit).unwrap();
    (history, root, view)
}

/// Supplies conflicting signed baseline and untrusted inputs at the `file` key.
pub(crate) fn baseline_and_untrusted_history() -> (
    VerifiedHistory,
    crate::identity::Digest,
    crate::identity::Digest,
    crate::identity::Digest,
    crate::identity::Digest,
) {
    let (mut history, baseline_root, baseline_view) = baseline_history();
    let (untrusted_root, bytes) = tree(vec![item(b"file", entry(b"untrusted"))], None);
    let commit = signed_record(
        untrusted_root,
        Vec::new(),
        Some(vec![receipt(
            untrusted_root,
            crate::refs::EntryOrigin::Current,
        )]),
        false,
    );
    let untrusted_view = commit.identity();
    history
        .insert_tree(untrusted_root, &[(untrusted_root, bytes)])
        .unwrap();
    history.insert_commit(commit).unwrap();
    (
        history,
        baseline_root,
        baseline_view,
        untrusted_root,
        untrusted_view,
    )
}

#[test]
fn prov_selector_presets_signed_key_names_terminal_public_key_bytes() {
    let (history, root, view) = baseline_history();
    let public_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let key_id: alloc::string::String = public_key
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect();
    let mut selector = Vec::new();
    crate::cbor::write_array(&mut selector, 2);
    crate::cbor::write_text(&mut selector, "signed-by-key");
    crate::cbor::write_text(&mut selector, &key_id);
    let context = TrustContext::new(
        &history,
        view,
        Selector::decode(&selector).unwrap(),
        "private",
        None,
    )
    .unwrap();
    assert!(context.accepts(root, b"file"));

    for invalid in ["issuer-key".to_string(), "A".repeat(64)] {
        let mut selector = Vec::new();
        crate::cbor::write_array(&mut selector, 2);
        crate::cbor::write_text(&mut selector, "signed-by-key");
        crate::cbor::write_text(&mut selector, &invalid);
        assert!(Selector::decode(&selector).is_err());
    }
}

#[test]
fn prov_entry_preserve_index_receipts_use_checked_opaque_keys() {
    let path = b"\0raw//key";
    let mut indexed = entry(b"unused");
    indexed.kind = crate::tree_format::EntryKind::Index {
        targets: vec![[1; 32]],
    };
    let node = crate::tree_format::Node {
        level: 0,
        items: crate::tree_format::NodeItems::Leaf(vec![item(path, indexed)]),
        props: None,
    };
    let bytes = crate::tree_format::encode_node_for(
        &node,
        true,
        MIN_CHUNK,
        crate::tree_format::TreeUse::Index,
    )
    .unwrap();
    let root = crate::identity::TERRANE_V1
        .calculate(crate::identity::IdentityKind::Node, &bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let mut current = receipt(root, crate::refs::EntryOrigin::Current);
    current.path = path.to_vec();
    let commit = signed_record(root, Vec::new(), Some(vec![current]), true);
    let view = commit.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    assert!(history.insert_tree(root, &[(root, bytes.clone())]).is_err());
    history.insert_index_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(commit).unwrap();
    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Strict),
        "private",
        Some("baseline"),
    )
    .unwrap();

    assert!(context.accepts(root, path));
}

#[test]
fn prov_selector_presets_candidate_decisions_bind_full_signed_entry() {
    let (history, root, view, untrusted_root, untrusted_view) = baseline_and_untrusted_history();
    let authentic = history
        .entry(&EntryLocation {
            commit: view,
            root,
            path: b"file".to_vec(),
        })
        .unwrap();
    let untrusted = history
        .entry(&EntryLocation {
            commit: untrusted_view,
            root: untrusted_root,
            path: b"file".to_vec(),
        })
        .unwrap();
    let context = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Strict),
        "private",
        Some("baseline"),
    )
    .unwrap();
    let mut changed_metadata = authentic.clone();
    changed_metadata.attrs_present = true;

    assert_eq!(context.view_root(), root);
    assert!(context.accepts_entry(root, b"file", &authentic));
    assert_eq!(
        context.producer_time_entry(root, b"file", &authentic),
        Some(100)
    );
    assert!(!context.accepts_entry(root, b"file", &untrusted));
    assert!(!context.accepts_entry(root, b"file", &changed_metadata));
    assert!(!context.accepts_entry(untrusted_root, b"file", &authentic));
    assert_eq!(context.producer_time_entry(root, b"file", &untrusted), None);
}

#[test]
fn prov_attribute_acceptance_does_not_borrow_content_acceptance() {
    let (original_root, original_bytes) = tree(vec![item(b"file", entry(b"target"))], None);
    let introduced = signed_record(
        original_root,
        Vec::new(),
        Some(vec![receipt(
            original_root,
            crate::refs::EntryOrigin::Current,
        )]),
        false,
    );
    let introducing = introduced.identity();
    let accepted = signed_record(original_root, vec![introducing], None, true);
    let accepting = accepted.identity();
    let mut annotated = entry(b"target");
    annotated.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    annotated.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", annotated)], None);
    let source = crate::refs::EntrySource {
        commit: accepting,
        root: original_root,
        path: b"file".to_vec(),
    };
    let mut produced_receipt = receipt(root, crate::refs::EntryOrigin::Source(source));
    produced_receipt.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Current,
    )]);
    let produced = signed_record(root, vec![accepting], Some(vec![produced_receipt]), false);
    let producing = produced.identity();
    let accepted_attribute = signed_record(root, vec![producing], None, true);
    let accepted_view = accepted_attribute.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(original_root, &[(original_root, original_bytes)])
        .unwrap();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    for commit in [introduced, accepted, produced, accepted_attribute] {
        history.insert_commit(commit).unwrap();
    }
    let mut selector = Vec::new();
    crate::cbor::write_array(&mut selector, 3);
    crate::cbor::write_text(&mut selector, "attr-by");
    crate::cbor::write_text(&mut selector, "hash.sha256");
    selector.extend_from_slice(Selector::preset(Preset::SignedBaseline).encode());
    let selector = Selector::decode(&selector).unwrap();
    let content = TrustContext::new(
        &history,
        producing,
        Selector::preset(Preset::SignedBaseline),
        "private",
        Some("baseline"),
    )
    .unwrap();
    let attribute = TrustContext::new(
        &history,
        producing,
        selector.clone(),
        "private",
        Some("baseline"),
    )
    .unwrap();
    let accepted_attribute = TrustContext::new(
        &history,
        accepted_view,
        selector,
        "private",
        Some("baseline"),
    )
    .unwrap();

    assert!(content.accepts(root, b"file"));
    assert!(!attribute.accepts(root, b"file"));
    assert!(accepted_attribute.accepts(root, b"file"));
}

#[test]
fn prov_attribute_producer_rejects_equal_value_inherited_on_changed_content() {
    let mut original_entry = entry(b"original");
    original_entry.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    original_entry.attrs_present = true;
    let (original_root, original_bytes) = tree(vec![item(b"file", original_entry)], None);
    let mut original_receipt = receipt(original_root, crate::refs::EntryOrigin::Current);
    original_receipt.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Current,
    )]);
    let original = signed_record(
        original_root,
        Vec::new(),
        Some(vec![original_receipt]),
        true,
    );
    let original_view = original.identity();
    let mut changed_entry = entry(b"changed");
    changed_entry.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    changed_entry.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", changed_entry)], None);
    let changed = signed_record(
        root,
        vec![original_view],
        Some(vec![receipt(root, crate::refs::EntryOrigin::Current)]),
        false,
    );
    let view = changed.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(original_root, &[(original_root, original_bytes)])
        .unwrap();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(original).unwrap();
    history.insert_commit(changed).unwrap();
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };

    assert_eq!(history.introducing_commit(&location), Ok(view));
    assert!(
        history
            .attribute_producer(&location, "hash.sha256")
            .is_err()
    );
}

#[test]
fn prov_external_sources_preserve_producers_without_granting_acceptance() {
    let mut annotated = entry(b"target");
    annotated.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    annotated.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", annotated)], None);
    let mut initial_receipt = receipt(root, crate::refs::EntryOrigin::Current);
    initial_receipt.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Current,
    )]);
    let introduced = signed_record(root, Vec::new(), Some(vec![initial_receipt]), false);
    let introducing = introduced.identity();
    let accepted = signed_record(root, vec![introducing], None, true);
    let accepting = accepted.identity();
    let source = crate::refs::EntrySource {
        commit: accepting,
        root,
        path: b"file".to_vec(),
    };
    let mut external_receipt = receipt(root, crate::refs::EntryOrigin::Source(source.clone()));
    external_receipt.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Source(source),
    )]);
    let imported = signed_record(root, Vec::new(), Some(vec![external_receipt]), false);
    let view = imported.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    for commit in [introduced, accepted, imported] {
        history.insert_commit(commit).unwrap();
    }
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };

    assert_eq!(history.introducing_commit(&location), Ok(introducing));
    assert_eq!(
        history.attribute_producer(&location, "hash.sha256"),
        Ok(introducing)
    );
    assert!(
        !history
            .acceptance_commits(&location, introducing)
            .unwrap()
            .contains(&accepting)
    );
    assert!(
        !history
            .attribute_acceptance_commits(&location, "hash.sha256", introducing)
            .unwrap()
            .contains(&accepting)
    );
    for inner in [Selector::preset(Preset::SignedBaseline), {
        let mut bytes = Vec::new();
        crate::cbor::write_array(&mut bytes, 2);
        crate::cbor::write_text(&mut bytes, "accepted-by");
        crate::cbor::write_array(&mut bytes, 2);
        crate::cbor::write_text(&mut bytes, "group");
        crate::cbor::write_text(&mut bytes, "baseline");
        Selector::decode(&bytes).unwrap()
    }] {
        let content =
            TrustContext::new(&history, view, inner.clone(), "private", Some("baseline")).unwrap();
        let mut attribute = Vec::new();
        crate::cbor::write_array(&mut attribute, 3);
        crate::cbor::write_text(&mut attribute, "attr-by");
        crate::cbor::write_text(&mut attribute, "hash.sha256");
        attribute.extend_from_slice(inner.encode());
        let attribute = TrustContext::new(
            &history,
            view,
            Selector::decode(&attribute).unwrap(),
            "private",
            Some("baseline"),
        )
        .unwrap();

        assert!(!content.accepts(root, b"file"));
        assert!(!attribute.accepts(root, b"file"));
    }
}

#[test]
fn prov_property_wrappers_resolve_inheritance_and_graft_overrides() {
    fn binding(value: &str, inherit: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        crate::cbor::write_map(&mut bytes, 2);
        crate::cbor::write_text(&mut bytes, "value");
        crate::cbor::write_text(&mut bytes, value);
        crate::cbor::write_text(&mut bytes, "inherit");
        bytes.push(if inherit { 0xf5 } else { 0xf4 });
        bytes
    }
    for inherit in [false, true] {
        let strict = binding("strict", inherit);
        let baseline = binding("baseline", false);
        let overridden = binding("attested", true);
        let graft_any = binding("any", false);
        let (child_root, child_bytes) = tree(
            vec![item(b"file", entry(b"target"))],
            Some(vec![crate::tree_format::Property {
                name: "trust",
                value: &overridden,
            }]),
        );
        let introduced = signed_record(
            child_root,
            Vec::new(),
            Some(vec![receipt(child_root, crate::refs::EntryOrigin::Current)]),
            true,
        );
        let introducing = introduced.identity();
        let mut graft = entry(b"unused");
        graft.kind = crate::tree_format::EntryKind::Tree {
            root: child_root,
            props: Some(vec![crate::tree_format::Property {
                name: "trust",
                value: &graft_any,
            }]),
        };
        let (root, bytes) = tree(
            vec![item(b"mount", graft)],
            Some(vec![
                crate::tree_format::Property {
                    name: "trust",
                    value: &strict,
                },
                crate::tree_format::Property {
                    name: "baseline",
                    value: &baseline,
                },
            ]),
        );
        let mut graft_receipt = receipt(root, crate::refs::EntryOrigin::Current);
        graft_receipt.path = b"mount".to_vec();
        let source = crate::refs::EntrySource {
            commit: introducing,
            root: child_root,
            path: b"file".to_vec(),
        };
        let commit = signed_record(
            root,
            Vec::new(),
            Some(vec![
                graft_receipt,
                receipt(child_root, crate::refs::EntryOrigin::Source(source)),
            ]),
            true,
        );
        let view = commit.identity();
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history
            .insert_tree(child_root, &[(child_root, child_bytes)])
            .unwrap();
        history.insert_tree(root, &[(root, bytes)]).unwrap();
        history.insert_commit(introduced).unwrap();
        history.insert_commit(commit).unwrap();
        let local = TrustContext::new(
            &history,
            view,
            Selector::preset(Preset::Any),
            "private",
            None,
        )
        .unwrap();
        let descendant = TrustContext::new(
            &history,
            view,
            Selector::preset(Preset::Strict),
            "private",
            None,
        )
        .unwrap();

        assert!(local.accepts(root, b"mount/file"));
        assert!(!descendant.accepts(root, b"mount/file"));
    }
}
