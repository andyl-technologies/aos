//! Verifies complete native disclosure coverage of independent signed input parents.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, StoreErrorKind};
use terrane_format::tree_format::Attribute;

fn file(plaintext: &[u8]) -> Entry<'static> {
    Entry {
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
    }
}

/// Certifies both actual input parents only after every destination origin checks.
///
/// # Panics
/// Panics if genuine setup fails, incomplete coverage is accepted, input parents
/// or source tuples change, private graphs transfer, or source-erased reopening fails.
pub(super) async fn certify_complete_parent_cuts() {
    let (source, authority, credentials) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let references = ["refs/heads/_/main", "refs/heads/_/alternate"];
    let contents = [
        b"the actual first private input".as_slice(),
        b"the actual second independent private input".as_slice(),
    ];
    let mut source_heads = Vec::new();
    let mut source_roots = Vec::new();
    for (reference, plaintext) in references.into_iter().zip(contents) {
        let mut selected = file(plaintext);
        if reference == references[1] {
            selected.attrs = vec![Attribute {
                name: "note",
                value: b"\x61x",
            }];
            selected.attrs_present = true;
        }
        let tree = Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: selected,
            }],
            materialization::properties(true),
            262144,
            TreeUse::Ordinary,
        )
        .unwrap();
        let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &tree);
        let mut proposal = authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        let mut session = source
            .begin(reference, authority.token(), "sdk")
            .await
            .unwrap();
        let head = source.advance(&mut session, proposal).await.unwrap();
        assert_eq!(
            source
                .guard()
                .original_commit(&head.commit)
                .unwrap()
                .baseline()
                .reference(),
            reference
        );
        let checked = source
            .guard()
            .read_snapshot(reference, authority.token(), b"/file", "sdk")
            .await
            .unwrap();
        let (location, _) = checked.history.locate(head.commit, b"file").unwrap();
        assert_eq!(
            checked.history.introducing_commit(&location).unwrap(),
            head.commit
        );
        if reference == references[1] {
            assert_eq!(
                checked
                    .history
                    .attribute_producer(&location, "note")
                    .unwrap(),
                head.commit
            );
        }
        source_heads.push(head);
        source_roots.push(tree.root_identity());
    }
    assert_ne!(source_heads[0].commit, source_heads[1].commit);
    let public = Tree::build(
        [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .zip(contents)
            .map(|(key, plaintext)| LeafItem {
                key: key.to_vec(),
                entry: file(plaintext),
            })
            .collect(),
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let proposal = |tree: &Tree<'_>| {
        let mut staged = materialization::stage_tree(request_file(Vec::new(), contents[0]), tree);
        staged.uploads.extend(
            request_file(Vec::new(), contents[1])
                .uploads
                .into_iter()
                .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
        );
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        proposal
    };
    let selections = || {
        references
            .into_iter()
            .enumerate()
            .map(|(index, reference)| DisclosureCommitSelection {
                source_reference: reference.into(),
                source_commit: source_heads[index].commit,
                source_path: b"/file".to_vec(),
                source_token: authority.token().to_vec(),
                destination_path: [b"/first".as_slice(), b"/second".as_slice()][index].to_vec(),
            })
            .collect::<Vec<_>>()
    };
    let mut target = destination
        .begin(references[0], destination_authority.token(), "sdk")
        .await
        .unwrap();
    let rejected = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&public),
                selections: selections().into_iter().take(1).collect(),
            },
        )
        .await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert!(target.record().is_none());
    let chunks = contents
        .into_iter()
        .map(|plaintext| {
            TERRANE_V1
                .calculate(IdentityKind::Chunk, plaintext)
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(destination.store().has(&chunks).await.unwrap(), [false; 2]);

    // Both content certificates are genuine, but the second input's private
    // attribute producer remains an independent uncovered proof edge.
    let mut copied = public.iter().cloned().collect::<Vec<_>>();
    copied[1].entry.attrs = vec![Attribute {
        name: "note",
        value: b"\x61x",
    }];
    copied[1].entry.attrs_present = true;
    let copied = Tree::build(
        copied,
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let rejected = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&copied),
                selections: selections(),
            },
        )
        .await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert!(target.record().is_none());
    assert_eq!(destination.store().has(&chunks).await.unwrap(), [false; 2]);

    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&public),
                selections: selections(),
            },
        )
        .await
        .unwrap();
    let checked = destination
        .guard()
        .read_snapshot(
            references[0],
            destination_authority.token(),
            b"/first",
            "sdk",
        )
        .await
        .unwrap();
    let record = checked.history.commit(&published.commit).unwrap().commit();
    assert_eq!(
        record.parents,
        source_heads
            .iter()
            .map(|head| head.commit)
            .collect::<Vec<_>>()
    );
    for (index, path) in [b"first".as_slice(), b"second".as_slice()]
        .into_iter()
        .enumerate()
    {
        let (location, _) = checked.history.locate(published.commit, path).unwrap();
        let receipt = record
            .profile_pair
            .entry_receipts
            .as_ref()
            .unwrap()
            .iter()
            .find(|receipt| receipt.root == location.root && receipt.path == location.path)
            .unwrap();
        assert!(receipt.disclosure_proof.is_some());
        let source = receipt.reintroduced_from.as_ref().unwrap();
        assert_eq!(source.commit, source_heads[index].commit);
        assert_eq!(source.root, source_roots[index]);
        assert_eq!(source.path, b"file");
        assert_eq!(
            checked.history.introducing_commit(&location).unwrap(),
            published.commit
        );
    }
    let private = source_heads
        .iter()
        .map(|head| {
            TERRANE_V1
                .from_digest(IdentityKind::Commit, &head.commit)
                .unwrap()
        })
        .chain(
            source_roots
                .iter()
                .map(|root| TERRANE_V1.from_digest(IdentityKind::Node, root).unwrap()),
        )
        .collect::<Vec<_>>();
    assert_eq!(destination.store().has(&private).await.unwrap(), [false; 4]);

    let source_root = source.store().root().to_owned();
    let source_control = source_root.with_file_name(format!(
        "{}-original-control",
        source_root.file_name().unwrap().to_string_lossy()
    ));
    let destination_root = destination.store().root().to_owned();
    let destination_config = destination.guard().config().clone();
    drop(checked);
    drop(target);
    drop(source);
    drop(authority);
    for path in [source_root, source_control, credentials] {
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
    for (path, plaintext) in [b"/first".as_slice(), b"/second".as_slice()]
        .into_iter()
        .zip(contents)
    {
        let checked = reopened
            .guard()
            .read_snapshot(references[0], destination_authority.token(), path, "sdk")
            .await
            .unwrap();
        let (location, _) = checked
            .history
            .locate(published.commit, &path[1..])
            .unwrap();
        let EntryKind::File { content, size, .. } = checked.history.entry(&location).unwrap().kind
        else {
            panic!("parent-cut file projection changed kind")
        };
        assert_eq!(
            reopened
                .guard()
                .read_content(&checked, path, content, size)
                .await
                .unwrap(),
            plaintext
        );
    }
    assert_eq!(reopened.store().has(&private).await.unwrap(), [false; 4]);
}
