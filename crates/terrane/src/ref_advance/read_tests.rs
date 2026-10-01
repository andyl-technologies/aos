//! Verifies current named-root policy boundaries for historical content reads.

#![allow(clippy::unwrap_used)]

use super::tests::{fixture, request, request_file, secret, token};
use super::{CommitRequest, StagedUpload};
use terrane_core::auth::Verb;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

fn graft_request() -> CommitRequest {
    let mut request = request_file(Vec::new(), b"private boundary");
    let child = request.commit.tree;
    let parent = Tree::build(
        vec![LeafItem {
            key: b"mount".to_vec(),
            entry: Entry {
                kind: EntryKind::Tree {
                    root: child,
                    props: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    request.commit.tree = parent.root_identity();
    request
        .uploads
        .extend(parent.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    request
}

#[tokio::test]
async fn child_acl_change_accepts_current_admin_on_its_actual_ancestor() {
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};

    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, graft_request())
        .await
        .unwrap();
    let terminal = [0x61; 32];
    let scoped = |admin| {
        let mut grants = vec![Grant::new(reference.to_owned(), Verbs::new(4).unwrap()).unwrap()];
        if admin {
            grants.push(Grant::new(format!("{reference}:/"), Verbs::new(16).unwrap()).unwrap());
        }
        Token::decode(&token())
            .unwrap()
            .attenuate(
                Attenuation {
                    not_after: None,
                    not_before: None,
                    grants: Some(grants),
                    caveats: Vec::new(),
                },
                &secret(),
                terrane_core::auth::public_key_from_secret(&terminal),
            )
            .unwrap()
            .encode()
    };
    let mut candidate = request_file(vec![first.commit], b"private boundary");
    let verified = coordinator
        .guard()
        .verified_tree(first.commit)
        .await
        .unwrap();
    {
        let parent = verified
            .evidence
            .tree(verified.evidence.root, 262144)
            .unwrap();
        let mut mount = parent.get(b"mount").unwrap().clone();
        let EntryKind::Tree { root, .. } = &mut mount.kind else {
            panic!("the fixture mount must be a tree");
        };
        let old_child = verified.evidence.tree(*root, 262144).unwrap();
        let child = Tree::build(
            old_child.iter().cloned().collect(),
            Some(vec![
                Property {
                    name: "acl",
                    value: b"\x82\x82\x66reader\x01\x82\x66writer\x18\x1f",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
            ]),
            262144,
            TreeUse::Ordinary,
        )
        .unwrap();
        *root = child.root_identity();
        let parent = Tree::build(
            vec![LeafItem {
                key: b"mount".to_vec(),
                entry: mount,
            }],
            parent.props().map(<[_]>::to_vec),
            262144,
            TreeUse::Ordinary,
        )
        .unwrap();
        candidate.commit.tree = parent.root_identity();
        candidate.uploads.retain(|upload| {
            !matches!(
                upload,
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    ..
                }
            )
        });
        for tree in [&child, &parent] {
            candidate
                .uploads
                .extend(tree.nodes().map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                }));
        }
    }
    candidate.terminal_secret = terminal;
    let rejected = CommitRequest {
        commit: candidate.commit.clone(),
        uploads: candidate.uploads.clone(),
        token: scoped(false),
        terminal_secret: terminal,
        surface: "sdk".to_owned(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    };
    assert!(
        coordinator
            .guard()
            .admit(reference, first.writer_epoch + 1, rejected)
            .await
            .is_err()
    );
    candidate.token = scoped(true);
    assert!(
        coordinator
            .guard()
            .authorize(
                reference,
                &candidate.token,
                Verb::Admin,
                &[b"/mount".to_vec()],
                "sdk"
            )
            .await
            .is_err()
    );
    let mut next_session = coordinator
        .begin(reference, &candidate.token, "sdk")
        .await
        .unwrap();
    let second = coordinator
        .advance(&mut next_session, candidate)
        .await
        .unwrap();
    assert_eq!(second.seq, first.seq + 1);

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn child_root_grant_is_valid_but_current_advance_requires_view_root() {
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};

    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let mut initial = request_file(Vec::new(), b"private boundary");
    let child = initial.commit.tree;
    let graft = |key: &[u8], root| LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Tree { root, props: None },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    };
    let docs = Tree::build(vec![graft(b"sub", child)], None, 262144, TreeUse::Ordinary).unwrap();
    initial
        .uploads
        .extend(docs.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let parent = Tree::build(
        vec![
            graft(b"docs", docs.root_identity()),
            graft(b"secret", child),
        ],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    initial.commit.tree = parent.root_identity();
    initial
        .uploads
        .extend(parent.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator.advance(&mut session, initial).await.unwrap();

    let terminal = [0x58; 32];
    let scoped = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    Grant::new(format!("{reference}:/docs/**"), Verbs::new(5).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &secret(),
            terrane_core::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();

    assert!(
        coordinator
            .guard()
            .authorize(
                reference,
                &scoped,
                Verb::Commit,
                &[b"/docs/sub".to_vec()],
                "sdk",
            )
            .await
            .is_ok()
    );
    assert!(
        coordinator
            .guard()
            .authorize(
                reference,
                &scoped,
                Verb::Commit,
                &[b"/secret".to_vec()],
                "sdk",
            )
            .await
            .is_err()
    );
    assert!(coordinator.begin(reference, &scoped, "sdk").await.is_err());
    let scoped_session = coordinator
        .begin_scoped(reference, &scoped, &[b"/docs/sub/file".to_vec()], "sdk")
        .await
        .unwrap();
    assert_eq!(scoped_session.scopes(), [b"/docs/sub".to_vec()]);
    assert_eq!(scoped_session.epoch(), first.writer_epoch + 1);
    assert_eq!(scoped_session.record(), Some(&first));
    assert!(
        coordinator
            .begin_scoped(reference, &scoped, &[], "sdk")
            .await
            .is_err()
    );
    assert!(
        coordinator
            .begin_scoped(reference, &scoped, &[b"/secret".to_vec()], "sdk",)
            .await
            .is_err()
    );
    assert!(
        coordinator
            .guard()
            .read_commit_snapshot(first.commit, &scoped, b"/docs/sub/file", "sdk",)
            .await
            .is_ok(),
        "a file within the authorized child root remains readable"
    );

    let mut candidate = request_file(vec![first.commit], b"changed child");
    let changed_docs = Tree::build(
        vec![graft(b"sub", candidate.commit.tree)],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let changed_parent = Tree::build(
        vec![
            graft(b"docs", changed_docs.root_identity()),
            graft(b"secret", child),
        ],
        parent.props().map(<[_]>::to_vec),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    candidate.commit.tree = changed_parent.root_identity();
    candidate.token = scoped;
    candidate.terminal_secret = terminal;
    for tree in [&changed_docs, &changed_parent] {
        candidate
            .uploads
            .extend(tree.nodes().map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            }));
    }
    assert!(
        coordinator
            .guard()
            .admit(reference, session.epoch(), candidate)
            .await
            .is_err(),
        "current admission still requests '/' before deriving the changed child root"
    );

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn ordinary_file_spelling_cannot_create_a_read_permission_boundary() {
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};

    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let record = coordinator
        .advance(&mut session, request_file(Vec::new(), b"flat file"))
        .await
        .unwrap();
    let terminal = [0x59; 32];
    let scoped = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    Grant::new(format!("{reference}:/file"), Verbs::new(1).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &secret(),
            terrane_core::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();

    assert!(
        coordinator
            .guard()
            .authorize(reference, &scoped, Verb::Read, &[b"/file".to_vec()], "sdk",)
            .await
            .is_err()
    );
    assert!(
        coordinator
            .guard()
            .read_commit_snapshot(record.commit, &scoped, b"/file", "sdk",)
            .await
            .is_err()
    );

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn deleting_named_policy_root_does_not_delegate_its_old_content_to_ancestor_acl() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, graft_request())
        .await
        .unwrap();
    let snapshot = coordinator
        .guard()
        .read_commit_snapshot(first.commit, &token(), b"/mount/file", "sdk")
        .await
        .unwrap();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"private boundary")
        .unwrap();
    let content = ContentRef::Inline(identity.terrane_v1_digest().unwrap());
    assert_eq!(
        coordinator
            .guard()
            .read_content(&snapshot, b"/mount/file", content, 16)
            .await
            .unwrap(),
        b"private boundary"
    );

    coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    assert!(
        coordinator
            .guard()
            .authorize(
                session.reference(),
                &token(),
                Verb::Read,
                &[b"/mount/file".to_vec()],
                "sdk"
            )
            .await
            .is_ok(),
        "the surviving ancestor grants read at this spelling"
    );
    assert!(
        coordinator
            .guard()
            .read_content(&snapshot, b"/mount/file", content, 16)
            .await
            .is_err(),
        "the removed named authority cannot fall back to that ancestor"
    );
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}
