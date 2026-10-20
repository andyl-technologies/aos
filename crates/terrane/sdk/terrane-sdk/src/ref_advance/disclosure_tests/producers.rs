//! Preserves independently public attribute producers through native disclosure.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};

fn attributed_tree(plaintext: &[u8], private: bool) -> Tree<'static> {
    Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(
                        TERRANE_V1
                            .calculate(IdentityKind::Chunk, plaintext)
                            .unwrap()
                            .terrane_v1_digest()
                            .unwrap(),
                    ),
                    link_id: None,
                },
                attrs: vec![terrane_format::tree_format::Attribute {
                    name: "note",
                    value: b"\x61y",
                }],
                attrs_present: true,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        materialization::properties(private),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
}

/// Preserves public attribute evidence while refusing identical private producer bytes.
///
/// # Panics
/// Panics if genuine setup fails, public producer evidence changes, private
/// attributes qualify through a content certificate, or source-erased reopening fails.
pub(super) async fn preserve_public_attribute_producer() {
    let (source, authority, credentials) = independent_factory("public").await;
    let (private_source, private_authority, private_credentials) =
        independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    assert_ne!(
        authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );
    let reference = "refs/heads/_/main";
    let plaintext = b"selected content keeps its independently public attribute";
    let mut source_session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), plaintext);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let introduced = source.advance(&mut source_session, proposal).await.unwrap();
    let public = attributed_tree(plaintext, false);
    let staged =
        materialization::stage_tree(request_file(vec![introduced.commit], plaintext), &public);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let produced = source.advance(&mut source_session, proposal).await.unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(produced.commit, b"file").unwrap();
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
    assert_ne!(introduced.commit, produced.commit);
    let original_authority = *source
        .guard()
        .original_commit(&produced.commit)
        .unwrap()
        .baseline()
        .authority()
        .id();

    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &public);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: produced.commit,
                    source_path: b"/file".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    let public_snapshot = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = public_snapshot
        .history
        .locate(published.commit, b"file")
        .unwrap();
    assert_eq!(
        public_snapshot
            .history
            .introducing_commit(&location)
            .unwrap(),
        published.commit
    );
    assert_eq!(
        public_snapshot
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        produced.commit
    );
    assert!(public_snapshot.history.commit(&produced.commit).is_some());
    assert_eq!(
        *destination
            .guard()
            .original_commit(&produced.commit)
            .unwrap()
            .baseline()
            .authority()
            .id(),
        original_authority
    );
    assert_ne!(
        *destination
            .guard()
            .original_commit(&published.commit)
            .unwrap()
            .baseline()
            .authority()
            .id(),
        original_authority
    );

    let mut private_session = private_source
        .begin(reference, private_authority.token(), "sdk")
        .await
        .unwrap();
    let private = attributed_tree(plaintext, true);
    let staged = materialization::stage_tree(private_file_request(Vec::new(), plaintext), &private);
    let mut proposal = private_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let private_head = private_source
        .advance(&mut private_session, proposal)
        .await
        .unwrap();
    let private_snapshot = private_source
        .guard()
        .read_snapshot(reference, private_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = private_snapshot
        .history
        .locate(private_head.commit, b"file")
        .unwrap();
    assert_eq!(
        private_snapshot
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        private_head.commit
    );
    let private_root = location.root;
    let selection = || {
        vec![DisclosureCommitSelection {
            source_reference: reference.into(),
            source_commit: private_head.commit,
            source_path: b"/file".to_vec(),
            source_token: private_authority.token().to_vec(),
            destination_path: b"/file".to_vec(),
        }]
    };
    let staged =
        materialization::stage_tree(request_file(vec![published.commit], plaintext), &public);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let rejected = destination
        .advance_disclosure(
            private_source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: selection(),
            },
        )
        .await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert_eq!(
        destination.store().ref_get(reference).await.unwrap(),
        Some(published.clone())
    );
    let private_graph = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &private_head.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private_root)
            .unwrap(),
    ];
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );

    // Equal attribute bytes do not substitute for the checked public producer.
    // The same private pair succeeds only after removing that unsupported copy.
    let plain = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(
                        TERRANE_V1
                            .calculate(IdentityKind::Chunk, plaintext)
                            .unwrap()
                            .terrane_v1_digest()
                            .unwrap(),
                    ),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let staged =
        materialization::stage_tree(request_file(vec![published.commit], plaintext), &plain);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let stripped = destination
        .advance_disclosure(
            private_source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: selection(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );

    let source_root = source.store().root().to_owned();
    let private_source_root = private_source.store().root().to_owned();
    let control = |root: &std::path::Path| {
        root.with_file_name(format!(
            "{}-original-control",
            root.file_name().unwrap().to_string_lossy()
        ))
    };
    let destination_root = destination.store().root().to_owned();
    let destination_config = destination.guard().config().clone();
    drop(checked);
    drop(public_snapshot);
    drop(private_snapshot);
    drop(source_session);
    drop(private_session);
    drop(target);
    drop(source);
    drop(private_source);
    drop(authority);
    drop(private_authority);
    for path in [
        control(&source_root),
        control(&private_source_root),
        source_root,
        private_source_root,
        credentials,
        private_credentials,
    ] {
        tokio::fs::remove_dir_all(path).await.unwrap();
    }
    drop(destination);
    let bucket = FileBucket::open(
        config(destination_root).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let reopened = NativeFixture::reopen(Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![destination_authority.issuer_key().clone()],
            destination_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    ))
    .await;
    let checked = reopened
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (old_location, _) = checked.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        checked
            .history
            .attribute_producer(&old_location, "note")
            .unwrap(),
        produced.commit
    );
    assert_eq!(
        *reopened
            .guard()
            .original_commit(&produced.commit)
            .unwrap()
            .baseline()
            .authority()
            .id(),
        original_authority
    );
    let (location, _) = checked.history.locate(stripped.commit, b"file").unwrap();
    let entry = checked.history.entry(&location).unwrap();
    assert!(!entry.attrs.iter().any(|attribute| attribute.name == "note"));
    let EntryKind::File { content, size, .. } = entry.kind else {
        panic!("stripped file projection changed kind")
    };
    assert_eq!(
        reopened
            .guard()
            .read_content(&checked, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
    assert_eq!(
        reopened.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );
}
