//! Publishes canonical algebra results with independent certificates per occurrence.

use super::*;
use crate::ref_advance::{CommitRequest, DisclosureCommitRequest, DisclosureCommitSelection};
use terrane_core::algebra::{Roots, flatten};
use terrane_core::identity::Digest;

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

fn properties(private: bool) -> Option<Vec<Property<'static>>> {
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

fn stage_tree(mut proposal: CommitRequest, tree: &Tree<'_>) -> CommitRequest {
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

pub(super) async fn certify_flattened_files() {
    let (source, source_authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"each canonical flattened occurrence has its own certificate";
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let child = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(EntryKind::File {
                mode: 0o644,
                size: plaintext.len() as u64,
                content: ContentRef::Inline(content.terrane_v1_digest().unwrap()),
                link_id: None,
            }),
        }],
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
    let mut staged = stage_tree(request_file(vec![child_head.commit], plaintext), &graft);
    staged
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut preparation = source_authority.commit_request(staged.commit.clone(), "sdk".into());
    preparation.uploads =
        stage_tree(request_file(vec![child_head.commit], plaintext), &graft).uploads;
    preparation
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    source
        .prepare_advance(&mut source_session, preparation)
        .await
        .expect("canonical graft preparation must preserve genuine current authority");
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
            |(properties, overrides)| terrane_core::properties::RootLayer {
                properties,
                overrides,
            },
        )
        .collect::<Vec<_>>();
    let child_layers = child_layers
        .iter()
        .map(
            |(properties, overrides)| terrane_core::properties::RootLayer {
                properties,
                overrides,
            },
        )
        .collect::<Vec<_>>();
    let parent_policy = terrane_core::properties::resolve(
        &parent_layers,
        source.guard().defaults_for(&snapshot.evidence),
    )
    .unwrap();
    let child_policy = terrane_core::properties::resolve(
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
                selections: [b"/mount".as_slice(), b"/mount/file".as_slice()]
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
    for path in [b"mount".as_slice(), b"mount/file".as_slice()] {
        let (location, _) = retained.history.locate(published.commit, path).unwrap();
        assert_eq!(
            retained.history.introducing_commit(&location).unwrap(),
            published.commit
        );
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
