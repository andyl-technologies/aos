//! Rejects raw special-kind trees without treating a file certificate as materialization.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};

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

fn special_tree(kind: EntryKind<'static>, usage: TreeUse) -> Tree<'static> {
    Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(kind),
        }],
        if usage == TreeUse::Index {
            None
        } else {
            materialization::properties(false)
        },
        262144,
        usage,
    )
    .unwrap()
}

/// Refuses genuine canonical special-kind inputs before effects and then publishes a file.
///
/// # Panics
/// Panics if genuine setup fails, a raw tree, whiteout, conflict or index receives
/// file-certificate authority, refusal writes staged objects, or the file control fails.
pub(super) async fn reject_special_projections() {
    let (source, authority, _) = independent_factory("public").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"a checked file does not authorize structural materialization";
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let file = EntryKind::File {
        mode: 0o644,
        size: plaintext.len() as u64,
        content: ContentRef::Inline(content.terrane_v1_digest().unwrap()),
        link_id: None,
    };
    let source_tree = special_tree(file.clone(), TreeUse::Ordinary);
    let mut source_session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &source_tree);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), source_head.commit);
    let (location, _) = checked.history.locate(source_head.commit, b"file").unwrap();
    let selected = checked.history.entry(&location).unwrap();
    assert!(matches!(selected.kind, EntryKind::File { .. }));

    let tree = special_tree(
        EntryKind::Tree {
            root: source_tree.root_identity(),
            props: None,
        },
        TreeUse::Ordinary,
    );
    let whiteout = special_tree(EntryKind::Whiteout, TreeUse::OverlayLayer);
    let conflict = special_tree(
        EntryKind::Conflict {
            candidates: vec![entry(file), entry(EntryKind::Directory { mode: 0o755 })],
            base: None,
        },
        TreeUse::Ordinary,
    );
    let profile = terrane_format::chunking::ChunkProfile::cdc_1m([0; 32]);
    let manifest = terrane_format::manifest::Manifest {
        size: plaintext.len() as u64,
        chunks: vec![terrane_format::manifest::ChunkRef {
            digest: content.terrane_v1_digest().unwrap(),
            length: plaintext.len() as u64,
        }],
        hashes: std::collections::BTreeMap::from([(
            "blake3".into(),
            blake3::hash(plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    };
    let manifest_bytes = manifest.encode(&profile).unwrap();
    let manifest_identity = manifest.identity(&profile).unwrap();
    let index = special_tree(
        EntryKind::Index {
            targets: vec![manifest_identity.terrane_v1_digest().unwrap()],
        },
        TreeUse::Index,
    );
    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let selections = || {
        vec![DisclosureCommitSelection {
            source_reference: reference.into(),
            source_commit: source_head.commit,
            source_path: b"/file".to_vec(),
            source_token: authority.token().to_vec(),
            destination_path: b"/file".to_vec(),
        }]
    };
    for (candidate, needs_child, needs_manifest, needs_plaintext) in [
        (&tree, true, false, true),
        (&whiteout, false, false, false),
        (&conflict, false, false, true),
        (&index, false, true, true),
    ] {
        let mut staged =
            materialization::stage_tree(request_file(Vec::new(), plaintext), candidate);
        if !needs_plaintext {
            staged
                .uploads
                .retain(|upload| !matches!(upload, StagedUpload::Chunk { .. }));
        }
        // Each refusal receives only its reachable canonical dependencies, so
        // unrelated-upload rejection cannot substitute for the projection check.
        if needs_child {
            staged
                .uploads
                .extend(source_tree.nodes().map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                }));
        }
        if needs_manifest {
            staged.uploads.push(StagedUpload::Meta {
                kind: IdentityKind::Manifest,
                bytes: manifest_bytes.clone(),
            });
        }
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        let rejected = destination
            .advance_disclosure(
                source.guard(),
                &mut target,
                DisclosureCommitRequest {
                    proposal,
                    selections: selections(),
                },
            )
            .await;
        assert!(
            matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
        );
        assert!(target.record().is_none());
        assert!(
            destination
                .store()
                .ref_get(reference)
                .await
                .unwrap()
                .is_none()
        );
        let graph = [
            content.clone(),
            manifest_identity.clone(),
            TERRANE_V1
                .from_digest(IdentityKind::Node, &candidate.root_identity())
                .unwrap(),
            TERRANE_V1
                .from_digest(IdentityKind::Node, &source_tree.root_identity())
                .unwrap(),
            TERRANE_V1
                .from_digest(IdentityKind::Commit, &source_head.commit)
                .unwrap(),
        ];
        assert_eq!(destination.store().has(&graph).await.unwrap(), [false; 5]);
    }

    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &source_tree);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: selections(),
            },
        )
        .await
        .unwrap();
    let checked = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        published.commit
    );
    let entry = checked.history.entry(&location).unwrap();
    let EntryKind::File { content, size, .. } = entry.kind else {
        panic!("the supported file control changed kind")
    };
    assert_eq!(
        destination
            .guard()
            .read_content(&checked, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
}
