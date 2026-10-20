//! Checks nested repeated-root disclosure against actual occurrence domains.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, StoreErrorKind};
use terrane_format::auth::{Attenuation, Caveat, Token, public_key_from_secret};
use terrane_format::identity::Digest;

fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn roots(names: &[&[u8]], child: Digest, private: bool) -> Tree<'static> {
    Tree::build(
        names
            .iter()
            .map(|name| LeafItem {
                key: name.to_vec(),
                entry: entry(EntryKind::Tree {
                    root: child,
                    props: None,
                }),
            })
            .collect(),
        materialization::properties(private),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
}

/// Certifies compatible repeated roots while checking the source's actual domain.
///
/// # Panics
/// Panics if genuine publication fails, an incompatible current-domain token
/// authorizes either occurrence, or repeated nested paths change checked content.
pub(super) async fn certify_repeated_roots() {
    let (source, authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"one retained root has two independently authorized occurrences";
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let leaf = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(EntryKind::File {
                mode: 0o644,
                size: plaintext.len() as u64,
                content: ContentRef::Inline(content.terrane_v1_digest().unwrap()),
                link_id: None,
            }),
        }],
        materialization::properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &leaf);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    let terminal = proposal.terminal_secret;
    proposal.uploads = staged.uploads;
    let introduced = source.advance(&mut session, proposal).await.unwrap();

    let wrapper = roots(&[b"inner"], leaf.root_identity(), true);
    let outer = roots(&[b"left", b"right"], wrapper.root_identity(), true);
    let mut staged =
        materialization::stage_tree(request_file(vec![introduced.commit], plaintext), &outer);
    for tree in [&wrapper, &leaf] {
        staged
            .uploads
            .extend(tree.nodes().map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            }));
    }
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let grafted = source.advance(&mut session, proposal).await.unwrap();
    let paths = [
        b"/left/inner/file".as_slice(),
        b"/right/inner/file".as_slice(),
    ];
    for path in paths {
        let checked = source
            .guard()
            .read_snapshot(reference, authority.token(), path, "sdk")
            .await
            .unwrap();
        let (location, _) = checked.history.locate(grafted.commit, &path[1..]).unwrap();
        assert_eq!(
            checked.history.introducing_commit(&location).unwrap(),
            introduced.commit
        );
    }

    let public_leaf = Tree::build(
        leaf.iter().cloned().collect(),
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let public_wrapper = roots(&[b"inner"], public_leaf.root_identity(), false);
    let public_outer = roots(&[b"left", b"right"], public_wrapper.root_identity(), false);
    let proposal = |tree: &Tree<'_>, children: &[&Tree<'_>]| {
        let mut staged = materialization::stage_tree(request_file(Vec::new(), plaintext), tree);
        for tree in children {
            staged
                .uploads
                .extend(tree.nodes().map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                }));
        }
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        proposal
    };
    let selections = |token: &[u8], relocated: bool| {
        paths
            .into_iter()
            .enumerate()
            .map(|(index, path)| DisclosureCommitSelection {
                source_reference: reference.into(),
                source_commit: grafted.commit,
                source_path: path.to_vec(),
                source_token: token.to_vec(),
                destination_path: if relocated {
                    [b"/left".as_slice(), b"/right".as_slice()][index].to_vec()
                } else {
                    path.to_vec()
                },
            })
            .collect()
    };
    let denied = Token::decode(authority.token())
        .unwrap()
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Domain("public".into())],
                ..Attenuation::default()
            },
            &terminal,
            public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    Token::decode(&denied)
        .unwrap()
        .verify(&[authority.issuer_key().clone()], 0)
        .unwrap();
    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();

    // The same public physical root may be placed beneath a more closed
    // effective graft policy. This is a valid reference, but this native
    // namespace cannot honor that placement. Checking only the outer public
    // domain would incorrectly accept the differently governed occurrence.
    let mut closing_items = public_wrapper.iter().cloned().collect::<Vec<_>>();
    let EntryKind::Tree { props, .. } = &mut closing_items[0].entry.kind else {
        panic!("wrapper lost its actual graft")
    };
    *props = Some(vec![Property {
        name: "domain",
        value: b"\x6eprivate:writer",
    }]);
    let closing_wrapper = Tree::build(
        closing_items,
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut mixed_items = public_outer.iter().cloned().collect::<Vec<_>>();
    let EntryKind::Tree { root, .. } = &mut mixed_items[1].entry.kind else {
        panic!("outer root lost its right graft")
    };
    *root = closing_wrapper.root_identity();
    let mixed = Tree::build(
        mixed_items,
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let offered = proposal(&mixed, &[&public_wrapper, &closing_wrapper, &public_leaf]);
    let mixed_evidence = crate::guard::TreeEvidence::load_tree(
        destination.store(),
        mixed.root_identity(),
        &offered.uploads,
        262144,
    )
    .await
    .unwrap();
    let policy_paths = [
        b"/left/inner/file".as_slice(),
        b"/right/inner/file".as_slice(),
        b"/right".as_slice(),
    ];
    let layers = policy_paths.map(|path| mixed_evidence.policy_path(path, 262144).unwrap());
    let bindings = layers
        .iter()
        .map(|layers| {
            layers
                .iter()
                .map(
                    |(properties, overrides)| terrane_format::properties::RootLayer {
                        properties,
                        overrides,
                    },
                )
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let policies = bindings
        .iter()
        .map(|layers| {
            terrane_format::properties::resolve(
                layers,
                destination.guard().defaults_for(&mixed_evidence),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let left = &policies[0];
    let right = &policies[1];
    let parent = &policies[2];
    assert_eq!(
        left.domain().unwrap(),
        terrane_format::properties::Domain::Public
    );
    assert_eq!(
        right.domain().unwrap(),
        terrane_format::properties::Domain::Private("writer")
    );
    terrane_format::properties::validate_commit(
        &[terrane_format::properties::EntryChange {
            entry: closing_wrapper.get(b"inner").unwrap(),
            properties: parent,
            reference_domains: &[terrane_format::properties::Domain::Public],
            graft_properties: Some(right),
        }],
        &[],
    )
    .unwrap();
    // The genuine credential permits both claimed domains and all affected
    // roots. Placement refusal must not be satisfied by token attenuation.
    let verified = Token::decode(destination_authority.token())
        .unwrap()
        .verify(&[destination_authority.issuer_key().clone()], 0)
        .unwrap();
    let authorized_roots = [
        terrane_format::auth::RequestRoot {
            path: b"/",
            domain: "public",
        },
        terrane_format::auth::RequestRoot {
            path: b"/left/inner",
            domain: "public",
        },
        terrane_format::auth::RequestRoot {
            path: b"/right/inner",
            domain: "private:writer",
        },
    ];
    verified
        .authorize(&terrane_format::auth::Request {
            reference: reference.as_bytes(),
            verb: terrane_format::auth::Verb::Commit,
            roots: &authorized_roots,
            now: 0,
            surface: "sdk",
            locality: &destination.guard().config().home,
            epochs: &[(reference, 0)],
        })
        .unwrap();
    let rejected = destination.advance(&mut target, offered).await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: "commit", pattern } if pattern == reference))
    );
    assert!(target.record().is_none());
    let mixed_nodes = mixed_evidence
        .roots
        .iter()
        .map(|root| TERRANE_V1.from_digest(IdentityKind::Node, root).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        destination.store().has(&mixed_nodes).await.unwrap(),
        vec![false; mixed_nodes.len()]
    );
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&content))
            .await
            .unwrap(),
        [false]
    );

    let rejected = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&public_outer, &[&public_wrapper, &public_leaf]),
                selections: selections(&denied, false),
            },
        )
        .await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: "read", pattern } if pattern == reference))
    );
    assert!(target.record().is_none());
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&content))
            .await
            .unwrap(),
        [false]
    );

    // A private cut cannot certify newly authored Tree descriptors. Retain
    // that complete-coverage refusal, then materialize the checked occurrences
    // as ordinary flattened files with independent certificates.
    let unsupported = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&public_outer, &[&public_wrapper, &public_leaf]),
                selections: selections(authority.token(), false),
            },
        )
        .await;
    assert!(
        matches!(unsupported, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert!(target.record().is_none());
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&content))
            .await
            .unwrap(),
        [false]
    );
    let flattened = Tree::build(
        paths
            .into_iter()
            .map(|path| LeafItem {
                key: if path == paths[0] {
                    b"left".to_vec()
                } else {
                    b"right".to_vec()
                },
                entry: public_leaf.get(b"file").unwrap().clone(),
            })
            .collect(),
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&flattened, &[]),
                selections: selections(authority.token(), true),
            },
        )
        .await
        .unwrap();
    for path in [b"/left".as_slice(), b"/right".as_slice()] {
        let checked = destination
            .guard()
            .read_snapshot(reference, destination_authority.token(), path, "sdk")
            .await
            .unwrap();
        let (location, _) = checked
            .history
            .locate(published.commit, &path[1..])
            .unwrap();
        let receipts = checked
            .history
            .commit(&published.commit)
            .unwrap()
            .commit()
            .profile_pair
            .entry_receipts
            .as_ref()
            .unwrap();
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| receipt.disclosure_proof.is_some())
                .count(),
            2
        );
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.root == location.root && receipt.path == location.path)
            .unwrap();
        let original = receipt.reintroduced_from.as_ref().unwrap();
        assert_eq!(original.commit, grafted.commit);
        assert_eq!(original.root, leaf.root_identity());
        assert_eq!(original.path, b"file");
        let EntryKind::File { content, size, .. } = checked.history.entry(&location).unwrap().kind
        else {
            panic!("file projection changed kind")
        };
        assert_eq!(
            destination
                .guard()
                .read_content(&checked, path, content, size)
                .await
                .unwrap(),
            plaintext
        );
    }
    let private_roots = [&outer, &wrapper, &leaf]
        .into_iter()
        .map(|tree| {
            TERRANE_V1
                .from_digest(IdentityKind::Node, &tree.root_identity())
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        destination.store().has(&private_roots).await.unwrap(),
        [false; 3]
    );

    // A completed public boundary can be retained as an ordinary graft input.
    // Actual public descriptor authoring precedes the second paired publication;
    // no private Tree entry is treated as a registered content projection.
    let public_snapshot = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/left", "sdk")
        .await
        .unwrap();
    let retained = public_snapshot
        .evidence
        .tree(public_snapshot.evidence.root, 262144)
        .unwrap();
    let retained_wrapper = roots(&[b"inner"], retained.root_identity(), false);
    let retained_outer = roots(
        &[b"left", b"right"],
        retained_wrapper.root_identity(),
        false,
    );
    let mut staged = materialization::stage_tree(
        request_file(vec![published.commit], plaintext),
        &retained_outer,
    );
    for tree in [&retained_wrapper, &retained] {
        staged
            .uploads
            .extend(tree.nodes().map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            }));
    }
    let mut authored = destination_authority.commit_request(staged.commit, "sdk".into());
    authored.uploads = staged.uploads;
    let nested = destination.advance(&mut target, authored).await.unwrap();
    let nested_paths = [
        b"/left/inner/left".as_slice(),
        b"/left/inner/right".as_slice(),
        b"/right/inner/left".as_slice(),
        b"/right/inner/right".as_slice(),
    ];
    for path in nested_paths {
        let checked = destination
            .guard()
            .read_snapshot(reference, destination_authority.token(), path, "sdk")
            .await
            .unwrap();
        let (location, _) = checked.history.locate(nested.commit, &path[1..]).unwrap();
        assert_eq!(
            checked.history.introducing_commit(&location).unwrap(),
            published.commit
        );
    }

    let (nested_destination, nested_authority, _) = independent_factory("public").await;
    let mut nested_target = nested_destination
        .begin(reference, nested_authority.token(), "sdk")
        .await
        .unwrap();
    let mut staged =
        materialization::stage_tree(request_file(Vec::new(), plaintext), &retained_outer);
    for tree in [&retained_wrapper, &retained] {
        staged
            .uploads
            .extend(tree.nodes().map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            }));
    }
    let mut proposal = nested_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let nested_published = nested_destination
        .advance_disclosure(
            destination.guard(),
            &mut nested_target,
            DisclosureCommitRequest {
                proposal,
                selections: nested_paths
                    .into_iter()
                    .map(|path| DisclosureCommitSelection {
                        source_reference: reference.into(),
                        source_commit: nested.commit,
                        source_path: path.to_vec(),
                        source_token: destination_authority.token().to_vec(),
                        destination_path: path.to_vec(),
                    })
                    .collect(),
            },
        )
        .await
        .inspect_err(|error| {
            if matches!(error, AdvanceError::Store(failure)
                if matches!(failure.kind(), StoreErrorKind::Denied { .. }))
            {
                crate::guard::trace_denial_phase("second-positive-nested-publication");
            }
        })
        .unwrap();
    for path in nested_paths {
        let checked = nested_destination
            .guard()
            .read_snapshot(reference, nested_authority.token(), path, "sdk")
            .await
            .unwrap();
        let (location, _) = checked
            .history
            .locate(nested_published.commit, &path[1..])
            .unwrap();
        let EntryKind::File { content, size, .. } = checked.history.entry(&location).unwrap().kind
        else {
            panic!("nested file projection changed kind")
        };
        assert_eq!(
            nested_destination
                .guard()
                .read_content(&checked, path, content, size)
                .await
                .unwrap(),
            plaintext
        );
    }
    assert_eq!(
        nested_destination
            .store()
            .has(&private_roots)
            .await
            .unwrap(),
        [false; 3]
    );
}
