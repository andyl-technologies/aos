//! Checks repeated public occurrences after genuine private source erasure.

use super::*;

/// Checks complete metadata reachability against genuine native publication.
///
/// # Panics
/// Panics if setup fails or actual traversal differs from the independent oracle.
pub(super) async fn gc_common_walk_native_repeated_occurrences_cut_erased_audit_sources_only() {
    use crate::ref_advance::disclosure_tests::{independent_factory, witness_support};
    use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
    let (source, source_authority, credentials) = independent_factory("private:writer").await;
    let source = witness_support::production_metadata(source, &source_authority).await;
    let (destination, authority, destination_credentials) = independent_factory("public").await;
    let destination = witness_support::production_metadata(destination, &authority).await;
    let plaintext = b"public occurrences retain independent producers after source erasure";
    let object = digest(IdentityKind::Chunk, plaintext);
    let properties = |private| {
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: if private {
                    b"\x6eprivate:writer".as_slice()
                } else {
                    b"\x66public".as_slice()
                },
            },
        ])
    };
    let private = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(plaintext),
        }],
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let mut source_writer = source
        .begin("refs/heads/_/main", source_authority.token(), "sdk")
        .await
        .assert_success();
    let private_head = source
        .advance(
            &mut source_writer,
            witness_support::proposal(&source_authority, Vec::new(), &private, &[plaintext]),
        )
        .await
        .assert_success();
    let projected = Tree::build(
        private.iter().cloned().collect(),
        properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let request = witness_support::proposal(&authority, Vec::new(), &projected, &[plaintext]);
    let public_secret = request.terminal_secret;
    let mut writer = destination
        .begin("refs/heads/_/main", authority.token(), "sdk")
        .await
        .assert_success();
    let public_head = destination
        .advance_disclosure(
            source.guard(),
            &mut writer,
            DisclosureCommitRequest {
                proposal: request,
                selections: vec![DisclosureCommitSelection {
                    source_reference: "refs/heads/_/main".into(),
                    source_commit: private_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .assert_success();
    drop(writer);
    drop(source_writer);
    drop(source_authority);
    witness_support::erase_index_source(source, credentials).await;
    let destination = witness_support::reopen_index(destination, &authority).await;

    // Native disclosure seals its own normalized public tree. Ordinary grafts
    // reuse that actual retained tree, including its genuine public introduction.
    let public_verified = destination
        .guard()
        .verified_tree(public_head.commit)
        .await
        .assert_success();
    let child = public_verified
        .evidence
        .tree(public_verified.evidence.root, 262144)
        .assert_success();
    let graft = || Entry {
        kind: EntryKind::Tree {
            root: child.root_identity(),
            props: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let owner = Tree::build(
        vec![
            LeafItem {
                key: b"a".to_vec(),
                entry: graft(),
            },
            LeafItem {
                key: b"b".to_vec(),
                entry: graft(),
            },
        ],
        properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let mut request =
        witness_support::proposal(&authority, vec![public_head.commit], &owner, &[plaintext]);
    request
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut writer = destination
        .begin("refs/heads/_/main", authority.token(), "sdk")
        .await
        .assert_success();
    let grafted = destination
        .advance(&mut writer, request)
        .await
        .assert_success();
    drop(writer);
    let destination = witness_support::reopen_index(destination, &authority).await;
    let identities = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &private_head.commit)
            .assert_success(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private.root_identity())
            .assert_success(),
    ];
    assert_eq!(
        destination.store().has(&identities).await.assert_success(),
        vec![false, false]
    );
    let mut public_record =
        AttrRecord::new(object, AttributeValue::Sha256([15; 32]), public_head.commit);
    public_record
        .sign(&public_verified.commit, &public_secret)
        .assert_success();
    let bytes = public_record.encode().assert_success();
    let public_record_hash = destination
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Attribute, &bytes).assert_success(),
        ))
        .await
        .assert_success()
        .terrane_v1_digest()
        .assert_success();
    let mut metadata_rows = Vec::new();
    for metadata in [child.root_identity(), grafted.commit, public_record_hash] {
        let row = AttrRecord::new(
            metadata,
            AttributeValue::Sha256([17; 32]),
            private_head.commit,
        );
        let encoded = row.encode().assert_success();
        metadata_rows.push(
            destination
                .store()
                .put(ContentUpload::Meta(
                    MetaUpload::new(IdentityKind::Attribute, &encoded).assert_success(),
                ))
                .await
                .assert_success()
                .terrane_v1_digest()
                .assert_success(),
        );
    }
    let original = destination
        .guard()
        .configured_original_authority()
        .assert_success();
    let collection = Collection::start(
        destination.guard(),
        &original,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(destination.store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let guard = crate::guard::collection_authority::historical_guard(
        destination.guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(destination.guard(), &original).assert_success();
    let root_histories = crate::selected_bridge::native_collection_roots::cycle(
        &guard,
        &consumed,
        &held,
        &observed,
        &collection.session,
        1,
    )
    .await
    .assert_success();
    let mut state = frontier(grafted.commit, false);
    let mut marks = BTreeSet::new();

    expand(
        &guard,
        &consumed,
        HistoryObservation::held(observed.identity()).tracked(&consumed),
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert!(!marks.contains(&private_head.commit));
    assert!(!marks.contains(&private.root_identity()));
    // Each raw row names the actually erased private S. Acquiring that producer
    // would fail; successful expansion proves these metadata-only claims did
    // not trigger its history verifier. Inspection still retains physical reads.
    assert!(metadata_rows.iter().all(|hash| !marks.contains(hash)));
    assert!(!guard.store().reads().assert_success().is_empty());
    for path in [b"/a".as_slice(), b"/b".as_slice()] {
        let context = ProofContext::new(grafted.commit, child.root_identity(), path.to_vec())
            .assert_success();
        for (kind, hash, flags) in [
            (2, child.root_identity(), ROOT),
            (0, object, 0),
            (7, public_record_hash, 0),
        ] {
            assert!(state.objects.contains(&ExpandedObject {
                kind,
                hash,
                flags,
                proof_context: Some(context.clone())
            }));
        }
    }
    assert!(
        state
            .pending
            .iter()
            .all(|item| item.hash == public_head.commit)
    );
    assert!(state.pending.iter().any(Pending::is_witness));
    assert!(
        guard
            .store()
            .identities()
            .assert_success()
            .iter()
            .all(|identity| {
                !identities.contains(identity)
                    && !metadata_rows.iter().any(|hash| identity.digest() == hash)
            })
    );
    let retained = consumed.finish().assert_success();
    assert!(!retained.disclosures.is_empty());
    assert!(
        retained
            .views
            .iter()
            .all(|view| view.view != private_head.commit)
    );
    drop(guard);
    drop(observed);
    drop(held);
    drop(holder);

    // The refusal is scoped to A's own completed batch and canonical `/`
    // occurrence. C's independent graft/parent edges are never relabeled A.
    let ambiguous = AttrRecord::new(
        object,
        AttributeValue::Sha256([16; 32]),
        private_head.commit,
    );
    let bytes = ambiguous.encode().assert_success();
    let record_hash = destination
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Attribute, &bytes).assert_success(),
        ))
        .await
        .assert_success()
        .terrane_v1_digest()
        .assert_success();
    let holder = SingleHeld::acquire(destination.store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let guard = crate::guard::collection_authority::historical_guard(
        destination.guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(destination.guard(), &original).assert_success();
    let root_histories = crate::selected_bridge::native_collection_roots::cycle(
        &guard,
        &consumed,
        &held,
        &observed,
        &collection.session,
        1,
    )
    .await
    .assert_success();
    let mut state = frontier(public_head.commit, false);
    let before = state.clone();
    let mut marks = BTreeSet::from([[77; 32]]);
    let before_marks = marks.clone();

    let error = expand(
        &guard,
        &consumed,
        HistoryObservation::held(observed.identity()).tracked(&consumed),
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_failure();

    let CollectionError::Store(error) = error else {
        panic!("expected exact missing proof")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    let proof = std::error::Error::source(&error)
        .assert_success()
        .downcast_ref::<history::MissingProof>()
        .assert_success();
    assert!(
        matches!(proof, history::MissingProof::AttributeProducerOccurrence { record, producer } if *record == record_hash && *producer == private_head.commit)
    );
    assert_eq!(state, before);
    assert_eq!(marks, before_marks);
    assert!(
        guard
            .store()
            .identities()
            .assert_success()
            .iter()
            .all(|identity| !identities.contains(identity))
    );
    assert!(
        consumed
            .finish()
            .assert_success()
            .views
            .iter()
            .all(|view| view.view != private_head.commit)
    );
    drop(guard);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    drop(authority);
    witness_support::erase_index_source(destination, destination_credentials).await;
}
