//! Exercises genuine side producers, canonical object/domain bindings, and memos.

use super::*;
use crate::{
    auth::RequestRoot,
    derived::{AttrRecord, AttributeName, AttributeValue, PlaintextHashes, verify_record_producer},
    properties::Defaults,
    refs::{CommitContext, EntryOrigin, EntryReceipt},
    tree_format::{Attribute, ContentRef, Entry, EntryKind, Property},
};

const DOMAIN: &str = "private:side";

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "test",
        private_domain: DOMAIN,
        home: "west",
    }
}

fn private_tree(items: Vec<crate::tree_format::LeafItem<'_>>) -> ([u8; 32], Vec<u8>) {
    domain_tree(items, DOMAIN)
}

fn domain_tree(items: Vec<crate::tree_format::LeafItem<'_>>, label: &str) -> ([u8; 32], Vec<u8>) {
    let mut domain = Vec::new();
    crate::cbor::write_text(&mut domain, label);
    tree(
        items,
        Some(vec![Property {
            name: "domain",
            value: &domain,
        }]),
    )
}

fn file<'a>(object: [u8; 32]) -> Entry<'a> {
    let mut entry = entry(b"");
    entry.kind = EntryKind::File {
        mode: 0o644,
        size: 3,
        content: ContentRef::Inline(object),
        link_id: None,
    };
    entry
}

fn authored(
    root: [u8; 32],
    parents: Vec<[u8; 32]>,
    receipts: Option<Vec<EntryReceipt>>,
    baseline: bool,
) -> VerifiedCommit {
    authored_in_domain(root, parents, receipts, baseline, DOMAIN)
}

fn authored_in_domain(
    root: [u8; 32],
    parents: Vec<[u8; 32]>,
    receipts: Option<Vec<EntryReceipt>>,
    baseline: bool,
    domain: &str,
) -> VerifiedCommit {
    let mut commit = signed_record(root, parents, receipts, baseline)
        .commit()
        .clone();
    with_request(|request| {
        let roots = [RequestRoot { path: b"/", domain }];
        let request = Request {
            roots: &roots,
            ..*request
        };
        commit.profile_pair.commit_context = Some(CommitContext::from_request(&request).unwrap());
        sign_authored(commit, &[9; 32], &issuer_keys(), &request, 4).unwrap()
    })
}

fn value() -> AttributeValue {
    let mut hashes = PlaintextHashes::new(3);
    hashes.update(b"abc").unwrap();
    hashes
        .finish()
        .unwrap()
        .attribute(AttributeName::Sha256)
        .unwrap()
}

fn record(producer: &VerifiedCommit) -> AttrRecord {
    let value = value();
    let mut record = AttrRecord {
        object: [7; 32],
        function: value.name().function(),
        value,
        producer: producer.identity(),
        signature: None,
    };
    record.sign(producer, &[9; 32]).unwrap();
    record
}

fn fixture() -> (
    VerifiedHistory,
    VerifiedCommit,
    VerifiedCommit,
    EntryLocation,
) {
    let (root, bytes) = private_tree(vec![
        item(b"file", file([7; 32])),
        item(b"other", file([7; 32])),
        item(b"unrelated", file([8; 32])),
    ]);
    let receipts = [b"file".as_slice(), b"other", b"unrelated"]
        .into_iter()
        .map(|path| EntryReceipt {
            root,
            path: path.to_vec(),
            origin: EntryOrigin::Current,
            attributes: None,
            reintroduced_from: None,
            disclosure_proof: None,
        })
        .collect();
    let introduced = authored(root, vec![], Some(receipts), false);
    let produced = authored(root, vec![introduced.identity()], None, true);
    let mut other_producer = authored(root, vec![introduced.identity()], None, false);
    // Distinguish the untrusted producer from the introduction on the same tree.
    let mut changed = other_producer.commit().clone();
    changed.message = "second producer".to_string();
    with_request(|request| {
        let roots = [RequestRoot {
            path: b"/",
            domain: DOMAIN,
        }];
        let request = Request {
            roots: &roots,
            ..*request
        };
        other_producer = sign_authored(changed, &[9; 32], &issuer_keys(), &request, 4).unwrap();
    });
    let location = EntryLocation {
        commit: produced.identity(),
        root,
        path: b"file".to_vec(),
    };
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let introduced_id = introduced.identity();
    history.insert_commit(introduced).unwrap();
    verify_fixture_scope(&mut history, introduced_id, defaults()).unwrap();
    history.insert_commit(produced.clone()).unwrap();
    verify_fixture_scope(&mut history, produced.identity(), defaults()).unwrap();
    history.insert_commit(other_producer.clone()).unwrap();
    verify_fixture_scope(&mut history, other_producer.identity(), defaults()).unwrap();
    (history, produced, other_producer, location)
}

fn binding(view: [u8; 32], path: &[u8]) -> SideAttributeBinding<'_> {
    SideAttributeBinding {
        view,
        path,
        producer_path: b"file",
        producer_defaults: defaults(),
        view_defaults: defaults(),
    }
}

fn attribute_selector(inner: &[u8]) -> Selector {
    let mut bytes = Vec::new();
    crate::cbor::write_array(&mut bytes, 3);
    crate::cbor::write_text(&mut bytes, "attr-by");
    crate::cbor::write_text(&mut bytes, "hash.sha256");
    bytes.extend_from_slice(inner);
    Selector::decode(&bytes).unwrap()
}

#[test]
fn prov_history_union_preserves_selected_side_record_contexts() {
    let (mut source, producer, _, location) = fixture();
    let evidence = verify_record_producer(&record(&producer), &source, &location).unwrap();
    source
        .insert_side_attribute(evidence, binding(location.commit, b"file"))
        .unwrap();
    let selector = attribute_selector(Selector::preset(Preset::Strict).encode());
    let expected = TrustContext::new(
        &source,
        location.commit,
        selector.clone(),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert!(expected.accepts_path(b"file"));
    let mut destination = VerifiedHistory::new(MIN_CHUNK);

    destination.append_verified(&source).unwrap();

    assert_eq!(destination.side_attributes, source.side_attributes);
    let context = TrustContext::new(
        &destination,
        location.commit,
        selector,
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert_eq!(context.canonical_context(), expected.canonical_context());
    assert!(context.accepts_path(b"file"));
    assert!(destination.entry(&location).unwrap().attrs.is_empty());
}

#[test]
fn prov_history_union_rejects_conflicting_selected_side_records_atomically() {
    let (history, producer, other_producer, location) = fixture();
    let mut first = history.clone();
    let evidence = verify_record_producer(&record(&producer), &first, &location).unwrap();
    first
        .insert_side_attribute(evidence, binding(location.commit, b"file"))
        .unwrap();
    let mut second = history;
    let other_location = EntryLocation {
        commit: other_producer.identity(),
        ..location.clone()
    };
    let evidence =
        verify_record_producer(&record(&other_producer), &second, &other_location).unwrap();
    second
        .insert_side_attribute(evidence, binding(location.commit, b"file"))
        .unwrap();
    assert_ne!(first.side_attributes, second.side_attributes);

    for (mut destination, source) in [(first.clone(), second.clone()), (second, first)] {
        let before = alloc::format!("{destination:?}");
        assert!(destination.append_verified(&source).is_err());
        assert_eq!(alloc::format!("{destination:?}"), before);
    }
}

#[test]
fn prov_side_attribute_authenticates_producer_without_inventing_inline_acceptance() {
    let (mut history, producer, _, location) = fixture();
    let evidence = verify_record_producer(&record(&producer), &history, &location).unwrap();
    assert!(
        history
            .attribute_producer(&location, "hash.sha256")
            .is_err()
    );
    history
        .insert_side_attribute(evidence, binding(location.commit, b"file"))
        .unwrap();
    assert!(history.entry(&location).unwrap().attrs.is_empty());
    let context = TrustContext::new(
        &history,
        location.commit,
        attribute_selector(Selector::preset(Preset::Strict).encode()),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert!(context.accepts_path(b"file"));
    validate_canonical_context(context.canonical_context()).unwrap();

    let mut accepted = Vec::new();
    crate::cbor::write_array(&mut accepted, 2);
    crate::cbor::write_text(&mut accepted, "accepted-by");
    accepted.extend_from_slice(Selector::preset(Preset::Strict).encode());
    let context = TrustContext::new(
        &history,
        location.commit,
        attribute_selector(&accepted),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert!(!context.accepts_path(b"file"));
    let wrong_domain = TrustContext::new(
        &history,
        location.commit,
        attribute_selector(Selector::preset(Preset::Strict).encode()),
        "private:other",
        Some("baseline"),
    )
    .unwrap();
    assert!(!wrong_domain.accepts_path(b"file"));
}

#[test]
fn prov_side_attribute_rejects_forged_record_unrelated_object_and_domain_evidence() {
    let (mut history, producer, _, location) = fixture();
    let signed = record(&producer);
    for field in [
        "producer",
        "object",
        "value",
        "function",
        "signature",
        "unsigned",
    ] {
        let mut forged = signed.clone();
        match field {
            "producer" => forged.producer = [8; 32],
            "object" => forged.object = [8; 32],
            "value" => forged.value = AttributeValue::Sha256([8; 32]),
            "function" => forged.function.version = "2".to_string(),
            "signature" => forged.signature.as_mut().unwrap()[0] ^= 1,
            "unsigned" => forged.signature = None,
            _ => unreachable!(),
        }
        assert!(
            verify_record_producer(&forged, &history, &location).is_err(),
            "{field}"
        );
    }
    let evidence = verify_record_producer(&signed, &history, &location).unwrap();
    assert!(
        history
            .insert_side_attribute(evidence.clone(), binding(location.commit, b"unrelated"))
            .is_err()
    );
    let wrong_path = SideAttributeBinding {
        producer_path: b"other",
        ..binding(location.commit, b"file")
    };
    assert!(
        history
            .insert_side_attribute(evidence.clone(), wrong_path)
            .is_err()
    );
    let caller_domain = SideAttributeBinding {
        view_defaults: Defaults {
            private_domain: "public",
            ..defaults()
        },
        ..binding(location.commit, b"file")
    };
    history
        .insert_side_attribute(evidence, caller_domain)
        .unwrap();
    assert!(
        TrustContext::new(
            &history,
            location.commit,
            attribute_selector(Selector::preset(Preset::Strict).encode()),
            DOMAIN,
            Some("baseline"),
        )
        .unwrap()
        .accepts_path(b"file")
    );
}

#[test]
fn prov_side_attribute_memo_and_context_distinguish_exact_records_and_witnesses() {
    let (history, producer, untrusted, location) = fixture();
    let first = record(&producer);
    let second = record(&untrusted);
    assert_ne!(first.identity().unwrap(), second.identity().unwrap());
    let first_evidence = verify_record_producer(&first, &history, &location).unwrap();
    let second_location = EntryLocation {
        commit: untrusted.identity(),
        ..location.clone()
    };
    let second_evidence = verify_record_producer(&second, &history, &second_location).unwrap();
    let selector = attribute_selector(Selector::preset(Preset::Strict).encode());
    let mut first_history = history.clone();
    first_history
        .insert_side_attribute(first_evidence.clone(), binding(location.commit, b"file"))
        .unwrap();
    let mut second_history = history.clone();
    second_history
        .insert_side_attribute(second_evidence.clone(), binding(location.commit, b"file"))
        .unwrap();
    let trusted = TrustContext::new(
        &first_history,
        location.commit,
        selector.clone(),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    let denied = TrustContext::new(
        &second_history,
        location.commit,
        selector.clone(),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert_ne!(trusted.canonical_context(), denied.canonical_context());
    assert!(trusted.accepts_path(b"file"));
    assert!(!denied.accepts_path(b"file"));
    assert!(
        first_history
            .insert_side_attribute(second_evidence.clone(), binding(location.commit, b"file"))
            .is_err()
    );
    first_history
        .insert_side_attribute(second_evidence, binding(location.commit, b"other"))
        .unwrap();
    let shared = TrustContext::new(
        &first_history,
        location.commit,
        selector,
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    for _ in 0..2 {
        assert!(shared.accepts_path(b"file"));
        assert!(!shared.accepts_path(b"other"));
    }
}

#[test]
fn prov_side_attribute_legacy_unsigned_requires_matching_inline_origin() {
    let value = value();
    let encoded = value.encode().unwrap();
    let mut inline = file([7; 32]);
    inline.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &encoded,
    }];
    inline.attrs_present = true;
    let (root, bytes) = private_tree(vec![item(b"file", inline)]);
    let mut origin = receipt(root, EntryOrigin::Current);
    origin.attributes = Some(vec![("hash.sha256".to_string(), EntryOrigin::Current)]);
    let producer = authored(root, vec![], Some(vec![origin]), true);
    let location = EntryLocation {
        commit: producer.identity(),
        root,
        path: b"file".to_vec(),
    };
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(producer.clone()).unwrap();
    verify_fixture_scope(&mut history, producer.identity(), defaults()).unwrap();
    let unsigned = AttrRecord {
        object: [7; 32],
        function: value.name().function(),
        value,
        producer: producer.identity(),
        signature: None,
    };
    let evidence = verify_record_producer(&unsigned, &history, &location).unwrap();
    history
        .insert_side_attribute(evidence, binding(location.commit, b"file"))
        .unwrap();
    let selector = attribute_selector(Selector::preset(Preset::Strict).encode());
    let context = TrustContext::new(
        &history,
        location.commit,
        selector,
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert!(context.accepts_path(b"file"));
    assert_eq!(
        history.attribute_producer(&location, "hash.sha256"),
        Ok(producer.identity())
    );
}

#[test]
fn prov_side_attribute_canonical_private_owner_rejects_foreign_routing_defaults() {
    let (private_root, private_bytes) = tree(vec![item(b"file", file([7; 32]))], None);
    let owner = crate::provenance::root_context::canonical_private_domain(private_root).unwrap();
    assert_ne!(owner, DOMAIN);
    let producer = authored_in_domain(
        private_root,
        vec![],
        Some(vec![receipt(private_root, EntryOrigin::Current)]),
        true,
        &owner,
    );
    let (target_root, target_bytes) = private_tree(vec![item(b"file", file([7; 32]))]);
    let target = authored(
        target_root,
        vec![],
        Some(vec![receipt(target_root, EntryOrigin::Current)]),
        false,
    );
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(private_root, &[(private_root, private_bytes)])
        .unwrap();
    history
        .insert_tree(target_root, &[(target_root, target_bytes)])
        .unwrap();
    for commit in [&producer, &target] {
        history.insert_commit(commit.clone()).unwrap();
        verify_fixture_scope(&mut history, commit.identity(), defaults()).unwrap();
    }
    let location = EntryLocation {
        commit: producer.identity(),
        root: private_root,
        path: b"file".to_vec(),
    };
    let evidence = verify_record_producer(&record(&producer), &history, &location).unwrap();

    // Both caller defaults falsely name the target's owner. A genuine producer
    // signature and matching object cannot transfer a different private scope.
    assert!(
        history
            .insert_side_attribute(evidence.clone(), binding(target.identity(), b"file"))
            .is_err()
    );
    assert!(history.side_attributes.is_empty());
    history
        .insert_side_attribute(evidence, binding(producer.identity(), b"file"))
        .unwrap();
    let selector = attribute_selector(Selector::preset(Preset::Strict).encode());
    assert!(
        TrustContext::new(
            &history,
            producer.identity(),
            selector.clone(),
            &owner,
            Some("baseline")
        )
        .unwrap()
        .accepts_path(b"file")
    );
    assert!(
        !TrustContext::new(
            &history,
            producer.identity(),
            selector,
            DOMAIN,
            Some("baseline")
        )
        .unwrap()
        .accepts_path(b"file")
    );
}

#[test]
fn prov_side_attribute_rejects_unfinished_target_until_canonical_scope_completes() {
    let (mut history, producer, _, location) = fixture();
    let signed_record = record(&producer);
    let identity = signed_record.identity().unwrap();
    let evidence = verify_record_producer(&signed_record, &history, &location).unwrap();
    let target = authored(location.root, vec![producer.identity()], None, false);
    history.insert_commit(target.clone()).unwrap();
    assert!(
        history
            .require_verified_context(producer.identity())
            .is_ok()
    );
    assert!(history.require_verified_context(target.identity()).is_err());

    assert!(
        history
            .insert_side_attribute(evidence.clone(), binding(target.identity(), b"file"))
            .is_err()
    );
    assert!(history.side_attributes.is_empty());
    assert_eq!(signed_record.identity().unwrap(), identity);
    verify_fixture_scope(&mut history, target.identity(), defaults()).unwrap();
    history
        .insert_side_attribute(evidence, binding(target.identity(), b"file"))
        .unwrap();
}

#[test]
fn prov_side_attribute_foreign_completed_evidence_needs_local_producer_admission() {
    let (history, producer, _, location) = fixture();
    let evidence = verify_record_producer(&record(&producer), &history, &location).unwrap();
    let (root, bytes) = private_tree(vec![
        item(b"file", file([7; 32])),
        item(b"other", file([7; 32])),
        item(b"unrelated", file([8; 32])),
    ]);
    assert_eq!(root, location.root);
    let introducing = history
        .commit(&producer.commit().parents[0])
        .unwrap()
        .clone();
    let mut local = VerifiedHistory::new(MIN_CHUNK);
    local.insert_tree(root, &[(root, bytes)]).unwrap();
    local.insert_commit(introducing.clone()).unwrap();
    local.insert_commit(producer.clone()).unwrap();

    assert!(
        local
            .insert_side_attribute(evidence.clone(), binding(producer.identity(), b"file"))
            .is_err()
    );
    assert!(local.side_attributes.is_empty());
    verify_fixture_scope(&mut local, introducing.identity(), defaults()).unwrap();
    verify_fixture_scope(&mut local, producer.identity(), defaults()).unwrap();
    local
        .insert_side_attribute(evidence, binding(producer.identity(), b"file"))
        .unwrap();
}

#[test]
fn prov_side_attribute_unsigned_inline_evidence_needs_completed_carrying_context() {
    let value = value();
    let encoded = value.encode().unwrap();
    let mut inline = file([7; 32]);
    inline.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &encoded,
    }];
    inline.attrs_present = true;
    let (root, bytes) = private_tree(vec![item(b"file", inline)]);
    let mut origin = receipt(root, EntryOrigin::Current);
    origin.attributes = Some(vec![("hash.sha256".to_string(), EntryOrigin::Current)]);
    let producer = authored(root, vec![], Some(vec![origin]), true);
    let carrier = authored(root, vec![producer.identity()], None, false);
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(producer.clone()).unwrap();
    verify_fixture_scope(&mut history, producer.identity(), defaults()).unwrap();
    history.insert_commit(carrier.clone()).unwrap();
    let mut unfinished = history.clone();
    verify_fixture_scope(&mut history, carrier.identity(), defaults()).unwrap();
    let location = EntryLocation {
        commit: carrier.identity(),
        root,
        path: b"file".to_vec(),
    };
    let record = AttrRecord {
        object: [7; 32],
        function: value.name().function(),
        value,
        producer: producer.identity(),
        signature: None,
    };
    let evidence = verify_record_producer(&record, &history, &location).unwrap();
    assert!(
        unfinished
            .require_verified_context(producer.identity())
            .is_ok()
    );
    assert!(
        unfinished
            .insert_side_attribute(evidence.clone(), binding(producer.identity(), b"file"))
            .is_err()
    );
    assert!(unfinished.side_attributes.is_empty());

    verify_fixture_scope(&mut unfinished, carrier.identity(), defaults()).unwrap();
    unfinished
        .insert_side_attribute(evidence, binding(producer.identity(), b"file"))
        .unwrap();
}

#[test]
fn prov_side_context_encoder_preserves_verified_legacy_carrying_witness() {
    let value = value();
    let encoded = value.encode().unwrap();
    let mut inline = file([7; 32]);
    inline.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &encoded,
    }];
    inline.attrs_present = true;
    let (root, bytes) = private_tree(vec![item(b"file", inline)]);
    let mut origin = receipt(root, EntryOrigin::Current);
    origin.attributes = Some(vec![("hash.sha256".to_string(), EntryOrigin::Current)]);
    let producer = authored(root, vec![], Some(vec![origin]), true);
    let carrier = authored(root, vec![producer.identity()], None, false);
    let location = EntryLocation {
        commit: carrier.identity(),
        root,
        path: b"file".to_vec(),
    };
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    for commit in [&producer, &carrier] {
        history.insert_commit(commit.clone()).unwrap();
        verify_fixture_scope(&mut history, commit.identity(), defaults()).unwrap();
    }

    let unsigned = AttrRecord {
        object: [7; 32],
        function: value.name().function(),
        value,
        producer: producer.identity(),
        signature: None,
    };
    let evidence = verify_record_producer(&unsigned, &history, &location).unwrap();
    assert_ne!(*evidence.producer(), evidence.location().commit);
    assert_eq!(*evidence.producer(), producer.identity());

    for with_side in [false, true] {
        if with_side {
            history
                .insert_side_attribute(evidence.clone(), binding(carrier.identity(), b"file"))
                .unwrap();
        }
        for preset in [
            Preset::Any,
            Preset::SignedBaseline,
            Preset::Strict,
            Preset::Attested,
        ] {
            for baseline in [None, Some(""), Some("baseline")] {
                let selector = Selector::preset(preset);
                let first = TrustContext::new(
                    &history,
                    carrier.identity(),
                    selector.clone(),
                    DOMAIN,
                    baseline,
                )
                .unwrap();
                let second =
                    TrustContext::new(&history, carrier.identity(), selector, DOMAIN, baseline)
                        .unwrap();
                let bytes = first.canonical_context();
                let mut decoder = crate::cbor::Decoder::new(bytes);
                assert_eq!(decoder.array(7).unwrap(), if with_side { 7 } else { 6 });
                assert_eq!(decoder.uint().unwrap(), if with_side { 2 } else { 1 });
                assert_eq!(bytes, second.canonical_context());
                assert_eq!(validate_canonical_context(bytes), Ok(()));
            }
        }
    }
    let context = TrustContext::new(
        &history,
        carrier.identity(),
        attribute_selector(Selector::preset(Preset::Strict).encode()),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert!(context.accepts_path(b"file"));
    assert_eq!(
        history.attribute_producer(&location, "hash.sha256"),
        Ok(producer.identity())
    );
}

#[test]
fn prov_side_attribute_legacy_commit_preserves_explicit_trusted_original_defaults() {
    let value = value();
    let encoded = value.encode().unwrap();
    let mut inline = file([7; 32]);
    inline.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &encoded,
    }];
    inline.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", inline)], None);
    let mut origin = receipt(root, EntryOrigin::Current);
    origin.attributes = Some(vec![("hash.sha256".to_string(), EntryOrigin::Current)]);
    let legacy = signed_record(root, vec![], Some(vec![origin]), true);
    let producer = with_request(|request| {
        let roots = [RequestRoot {
            path: b"/",
            domain: DOMAIN,
        }];
        let original = Request {
            roots: &roots,
            ..*request
        };
        sign(
            legacy.commit().clone(),
            &[9; 32],
            &issuer_keys(),
            &original,
            4,
        )
        .unwrap()
    });
    assert!(producer.commit().profile_pair.commit_context.is_none());
    let location = EntryLocation {
        commit: producer.identity(),
        root,
        path: b"file".to_vec(),
    };
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(producer.clone()).unwrap();
    let unsigned = AttrRecord {
        object: [7; 32],
        function: value.name().function(),
        value,
        producer: producer.identity(),
        signature: None,
    };
    let evidence = verify_record_producer(&unsigned, &history, &location).unwrap();

    history
        .insert_side_attribute(evidence, binding(producer.identity(), b"file"))
        .unwrap();
    let context = TrustContext::new(
        &history,
        producer.identity(),
        attribute_selector(Selector::preset(Preset::Strict).encode()),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert!(context.accepts_path(b"file"));
}
