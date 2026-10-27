//! Publishes canonical algebra results with independent certificates per occurrence.

use super::*;
use crate::ref_advance::{CommitRequest, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{RefStore, StoreErrorKind};
use terrane_format::algebra::{Roots, flatten};
use terrane_format::identity::Digest;

struct Forest(Vec<Tree<'static>>);

impl<'a> Roots<'a> for Forest {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
        self.0.iter().find(|tree| tree.root_identity() == *identity)
    }
}

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

/// Supplies actual public or private root policy for native materialization fixtures.
pub(super) fn properties(private: bool) -> Option<Vec<Property<'static>>> {
    Some(vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: if private {
                b"\x6eprivate:writer"
            } else {
                b"\x66public"
            },
        },
    ])
}

/// Stages every canonical node of an actual materialized tree.
pub(super) fn stage_tree(mut proposal: CommitRequest, tree: &Tree<'_>) -> CommitRequest {
    proposal.commit.tree = tree.root_identity();
    proposal.uploads.retain(|upload| {
        !matches!(
            upload,
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    proposal
        .uploads
        .extend(tree.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    proposal
}

fn stage_graft(
    parent: Digest,
    plaintext: &[u8],
    graft: &Tree<'_>,
    child: &Tree<'_>,
) -> CommitRequest {
    let mut staged = stage_tree(request_file(vec![parent], plaintext), graft);
    staged
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    staged
}

/// Preserves independently checked entry and attribute origins across a graft.
///
/// # Panics
/// Panics if actual source publication fails or relocation changes either checked
/// producer. Private attributes remain entirely within the private source.
pub(super) async fn preserve_relocated_attribute_producer() {
    let (source, authority, _) = independent_factory("private:writer").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"content predates its independent private attribute producer";
    let mut session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = private_file_request(Vec::new(), plaintext);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let introduced = source.advance(&mut session, proposal).await.unwrap();

    let snapshot = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot.history.locate(introduced.commit, b"file").unwrap();
    let mut edited = snapshot.history.entry(&location).unwrap();
    let attribute = edited
        .attrs
        .iter_mut()
        .find(|attribute| attribute.name == "note")
        .unwrap();
    attribute.value = b"\x61y";
    let child = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: edited,
        }],
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let staged = stage_tree(request_file(vec![introduced.commit], plaintext), &child);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let produced = source.advance(&mut session, proposal).await.unwrap();
    assert_ne!(introduced.commit, produced.commit);

    let graft = Tree::build(
        vec![LeafItem {
            key: b"mount".to_vec(),
            entry: entry(EntryKind::Tree {
                root: child.root_identity(),
                props: None,
            }),
        }],
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let staged = stage_graft(produced.commit, plaintext, &graft, &child);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let relocated = source.advance(&mut session, proposal).await.unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/mount/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked
        .history
        .locate(relocated.commit, b"mount/file")
        .unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        introduced.commit
    );
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        produced.commit
    );
    assert_ne!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        relocated.commit
    );
    assert_eq!(
        checked
            .history
            .entry(&location)
            .unwrap()
            .attrs
            .iter()
            .find(|attribute| attribute.name == "note")
            .unwrap()
            .value,
        b"\x61y"
    );
}

/// Preserves a carried root's producers when replacing another graft.
///
/// # Panics
/// Panics if genuine private publication fails or the displaced occupant's
/// matching content and attributes override the carried root's checked origins.
pub(super) async fn preserve_replacement_graft_producers() {
    let (source, authority, _) = independent_factory("private:writer").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"equal bytes do not select the displaced graft producer";
    let mut session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = private_file_request(Vec::new(), plaintext);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let introduced = source.advance(&mut session, proposal).await.unwrap();
    let snapshot = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot.history.locate(introduced.commit, b"file").unwrap();
    let original = snapshot.history.entry(&location).unwrap();
    let carried = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: original.clone(),
        }],
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut different = original;
    match &mut different.kind {
        EntryKind::File { mode, .. } => *mode = 0o600,
        _ => panic!("fixture must contain an actual file"),
    }
    let occupied = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: different,
        }],
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_ne!(carried.root_identity(), occupied.root_identity());
    let graft = |mount| {
        Tree::build(
            vec![
                LeafItem {
                    key: b"carried".to_vec(),
                    entry: entry(EntryKind::Tree {
                        root: carried.root_identity(),
                        props: None,
                    }),
                },
                LeafItem {
                    key: b"mount".to_vec(),
                    entry: entry(EntryKind::Tree {
                        root: mount,
                        props: None,
                    }),
                },
            ],
            properties(true),
            262144,
            TreeUse::Ordinary,
        )
        .unwrap()
    };
    let parent = graft(occupied.root_identity());
    let mut staged = stage_graft(introduced.commit, plaintext, &parent, &carried);
    staged
        .uploads
        .extend(occupied.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let displaced = source.advance(&mut session, proposal).await.unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/mount/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked
        .history
        .locate(displaced.commit, b"mount/file")
        .unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        displaced.commit
    );
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        displaced.commit
    );

    let replacement = graft(carried.root_identity());
    let mut staged = stage_graft(displaced.commit, plaintext, &replacement, &carried);
    staged
        .uploads
        .extend(occupied.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let replaced = source.advance(&mut session, proposal).await.unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/mount/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked
        .history
        .locate(replaced.commit, b"mount/file")
        .unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        introduced.commit
    );
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        introduced.commit
    );
}

/// Certifies each canonical flattened occurrence under actual paired authority.
///
/// # Panics
/// Panics if genuine native setup or algebra fails, denied token/domain requests
/// publish, source paths share a certificate, or retained public evidence fails.
pub(super) async fn certify_flattened_files() {
    let (source, source_authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"each canonical flattened occurrence has its own certificate";
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let child = Tree::build(
        [b"file".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|path| LeafItem {
                key: path.to_vec(),
                entry: entry(EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(content.terrane_v1_digest().unwrap()),
                    link_id: None,
                }),
            })
            .collect(),
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut source_session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = stage_tree(request_file(Vec::new(), plaintext), &child);
    let mut proposal = source_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let child_head = source.advance(&mut source_session, proposal).await.unwrap();

    let graft = Tree::build(
        vec![LeafItem {
            key: b"mount".to_vec(),
            entry: entry(EntryKind::Tree {
                root: child.root_identity(),
                props: None,
            }),
        }],
        properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    // Retained-root receipts do not replace either current Commit authority or
    // domain compatibility. Both refusals leave the actual whole head intact.
    let staged = stage_graft(child_head.commit, plaintext, &graft, &child);
    let mut denied = source_authority.commit_request(staged.commit, "sdk".into());
    denied.uploads = staged.uploads;
    let terminal = [0x6a; 32];
    denied.token = terrane_format::auth::Token::decode(source_authority.token())
        .unwrap()
        .attenuate(
            terrane_format::auth::Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    terrane_format::auth::Grant::new(
                        reference.into(),
                        terrane_format::auth::Verbs::new(1).unwrap(),
                    )
                    .unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &denied.terminal_secret,
            terrane_format::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    denied.terminal_secret = terminal;
    assert!(matches!(source.advance(&mut source_session, denied).await,
        Err(crate::ref_advance::AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: "commit", .. })));
    assert_eq!(
        source.store().ref_get(reference).await.unwrap(),
        Some(child_head.clone())
    );
    let incompatible = Tree::build(
        graft
            .iter()
            .map(|item| LeafItem {
                key: item.key.clone(),
                entry: item.entry.clone(),
            })
            .collect(),
        properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let staged = stage_graft(child_head.commit, plaintext, &incompatible, &child);
    let mut denied = source_authority.commit_request(staged.commit, "sdk".into());
    denied.uploads = staged.uploads;
    assert!(matches!(source.advance(&mut source_session, denied).await,
        Err(crate::ref_advance::AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: "commit", .. })));
    assert_eq!(
        source.store().ref_get(reference).await.unwrap(),
        Some(child_head.clone())
    );

    let staged = stage_graft(child_head.commit, plaintext, &graft, &child);
    let mut proposal = source_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let graft_head = source.advance(&mut source_session, proposal).await.unwrap();

    // Read the genuine signed graft under current source authority before using
    // the canonical algebra. Both policy layers resolve from this actual view.
    let snapshot = source
        .guard()
        .read_snapshot(reference, source_authority.token(), b"/mount/file", "sdk")
        .await
        .unwrap();
    let parent_layers = snapshot.evidence.policy_path(b"/", 262144).unwrap();
    let child_layers = snapshot
        .evidence
        .policy_path(b"/mount/file", 262144)
        .unwrap();
    let parent_layers = parent_layers
        .iter()
        .map(
            |(properties, overrides)| terrane_format::properties::RootLayer {
                properties,
                overrides,
            },
        )
        .collect::<Vec<_>>();
    let child_layers = child_layers
        .iter()
        .map(
            |(properties, overrides)| terrane_format::properties::RootLayer {
                properties,
                overrides,
            },
        )
        .collect::<Vec<_>>();
    let parent_policy = terrane_format::properties::resolve(
        &parent_layers,
        source.guard().defaults_for(&snapshot.evidence),
    )
    .unwrap();
    let child_policy = terrane_format::properties::resolve(
        &child_layers,
        source.guard().defaults_for(&snapshot.evidence),
    )
    .unwrap();
    let forest = Forest(vec![child]);
    let prepared = flatten(&graft, b"mount", &forest, &parent_policy, &child_policy).unwrap();
    let flattened = prepared.materialize(&graft).unwrap();
    assert!(matches!(
        flattened.get(b"mount").unwrap().kind,
        EntryKind::Directory { .. }
    ));
    assert!(matches!(
        flattened.get(b"mount/file").unwrap().kind,
        EntryKind::File { .. }
    ));
    let staged = stage_tree(request_file(vec![graft_head.commit], plaintext), &flattened);
    let mut proposal = source_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let flattened_head = source.advance(&mut source_session, proposal).await.unwrap();

    let mut destination_session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let empty = Tree::build(Vec::new(), properties(false), 262144, TreeUse::Ordinary).unwrap();
    let staged = stage_tree(request(Vec::new()), &empty);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let baseline = destination
        .advance(&mut destination_session, proposal)
        .await
        .unwrap();
    let public = Tree::build(
        flattened
            .iter()
            .map(|item| LeafItem {
                key: item.key.clone(),
                entry: item.entry.clone(),
            })
            .collect(),
        properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let staged = stage_tree(request(vec![baseline.commit]), &public);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut destination_session,
            DisclosureCommitRequest {
                proposal,
                selections: [
                    b"/mount".as_slice(),
                    b"/mount/file".as_slice(),
                    b"/mount/second".as_slice(),
                ]
                .into_iter()
                .map(|path| DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: flattened_head.commit,
                    source_path: path.to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: path.to_vec(),
                })
                .collect(),
            },
        )
        .await
        .unwrap();
    let retained = destination
        .guard()
        .read_snapshot(
            reference,
            destination_authority.token(),
            b"/mount/file",
            "sdk",
        )
        .await
        .unwrap();
    let receipts = retained
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
        3
    );
    for path in [
        b"mount".as_slice(),
        b"mount/file".as_slice(),
        b"mount/second".as_slice(),
    ] {
        let (location, _) = retained.history.locate(published.commit, path).unwrap();
        assert_eq!(
            retained.history.introducing_commit(&location).unwrap(),
            published.commit
        );
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.path == path)
            .unwrap();
        let selected = receipt.reintroduced_from.as_ref().unwrap();
        assert_eq!(selected.commit, flattened_head.commit);
        assert_eq!(selected.path, path);
        assert!(receipt.disclosure_proof.is_some());
    }
    assert_eq!(
        destination
            .guard()
            .read_content(
                &retained,
                b"/mount/file",
                ContentRef::Inline(content.terrane_v1_digest().unwrap()),
                plaintext.len() as u64
            )
            .await
            .unwrap(),
        plaintext
    );
    assert_eq!(
        destination
            .store()
            .has(&[
                TERRANE_V1
                    .from_digest(IdentityKind::Commit, &baseline.commit)
                    .unwrap(),
                TERRANE_V1
                    .from_digest(IdentityKind::Commit, &flattened_head.commit)
                    .unwrap(),
                TERRANE_V1
                    .from_digest(IdentityKind::Node, &graft.root_identity())
                    .unwrap()
            ])
            .await
            .unwrap(),
        vec![true, false, false]
    );
}
