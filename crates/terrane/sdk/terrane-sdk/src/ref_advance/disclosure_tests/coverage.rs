//! Refuses real uncovered private origins and an unrelated native parent cut.

use super::*;
use crate::ref_advance::{
    AdvanceError, CommitRequest, DisclosureCommitRequest, DisclosureCommitSelection,
};
use crate::selected_bridge::native_guard::disclosure::{
    CertificateMutation, corrupt_next_certificate,
};
use crate::store::{InvalidReason, StoreErrorKind};
use terrane_format::tree_format::Attribute;

fn file(
    plaintext: &[u8],
    attrs: Vec<Attribute<'static>>,
    provenance: Option<[u8; 32]>,
) -> Entry<'static> {
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
        attrs_present: !attrs.is_empty(),
        attrs,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance,
    }
}

fn target(plaintext: &[u8], sibling: Option<(&[u8], [u8; 32])>) -> CommitRequest {
    let mut items = vec![LeafItem {
        key: b"file".to_vec(),
        entry: file(plaintext, Vec::new(), None),
    }];
    if let Some((secret, origin)) = sibling {
        items.push(LeafItem {
            key: b"hidden".to_vec(),
            entry: file(secret, Vec::new(), Some(origin)),
        });
    }
    let tree = Tree::build(
        items,
        super::materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut staged = super::materialization::stage_tree(request_file(Vec::new(), plaintext), &tree);
    if let Some((secret, _)) = sibling {
        staged.uploads.extend(
            request_file(Vec::new(), secret)
                .uploads
                .into_iter()
                .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
        );
    }
    staged
}

/// Refuses incomplete private boundaries before any selected ref or chunk transfer.
///
/// # Panics
/// Panics if genuine setup fails, an uncovered origin or unrelated parent is
/// accepted, a mutation misses actual signing, or the positive control fails.
pub(super) async fn reject_incomplete_boundaries() {
    let (source, authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"the checked selection alone may cross the boundary";
    let secret = b"an uncovered genuine private sibling";
    let tree = Tree::build(
        vec![
            LeafItem {
                key: b"file".to_vec(),
                entry: file(
                    plaintext,
                    vec![Attribute {
                        name: "note",
                        value: b"\x61x",
                    }],
                    None,
                ),
            },
            LeafItem {
                key: b"hidden".to_vec(),
                entry: file(secret, Vec::new(), None),
            },
        ],
        super::materialization::properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut staged = super::materialization::stage_tree(request_file(Vec::new(), plaintext), &tree);
    staged.uploads.extend(
        request_file(Vec::new(), secret)
            .uploads
            .into_iter()
            .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
    );
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let mut source_session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    for path in [b"file".as_slice(), b"hidden".as_slice()] {
        let (location, _) = checked.history.locate(source_head.commit, path).unwrap();
        assert_eq!(
            checked.history.introducing_commit(&location).unwrap(),
            source_head.commit
        );
    }
    let (location, _) = checked.history.locate(source_head.commit, b"file").unwrap();
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        source_head.commit
    );

    let mut unrelated = source
        .begin("refs/heads/_/unrelated", authority.token(), "sdk")
        .await
        .unwrap();
    let staged = private_file_request(Vec::new(), b"a genuine unrelated branch commit");
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let unrelated_head = source.advance(&mut unrelated, proposal).await.unwrap();
    assert_ne!(source_head.commit, unrelated_head.commit);
    assert_eq!(
        source
            .guard()
            .original_commit(&unrelated_head.commit)
            .unwrap()
            .baseline()
            .reference(),
        "refs/heads/_/unrelated",
    );
    assert!(checked.history.commit(&unrelated_head.commit).is_none());
    let mut session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let request = |staged: CommitRequest| {
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        DisclosureCommitRequest {
            proposal,
            selections: vec![DisclosureCommitSelection {
                source_reference: reference.into(),
                source_commit: source_head.commit,
                source_path: b"/file".to_vec(),
                source_token: authority.token().to_vec(),
                destination_path: b"/file".to_vec(),
            }],
        }
    };
    let sibling = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            request(target(plaintext, Some((secret, source_head.commit)))),
        )
        .await;
    assert!(
        matches!(sibling, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: "commit", pattern } if pattern == reference))
    );
    assert!(session.record().is_none());
    let attributes = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            request(request_file(Vec::new(), plaintext)),
        )
        .await;
    assert!(
        matches!(attributes, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert!(session.record().is_none());
    let witness = corrupt_next_certificate(
        destination.store().root(),
        CertificateMutation::UnanchoredParent(unrelated_head.commit),
    )
    .unwrap();
    let parent = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            request(target(plaintext, None)),
        )
        .await;
    assert!(
        witness.applied(),
        "unrelated actual parent never reached source signing: {parent:?}"
    );
    assert!(
        matches!(parent, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert!(session.record().is_none());
    assert!(matches!(
        destination.guard().original_commit(&unrelated_head.commit),
        Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
    ));
    let unrelated_identity = TERRANE_V1
        .from_digest(IdentityKind::Commit, &unrelated_head.commit)
        .unwrap();
    assert_eq!(
        destination
            .store()
            .has(&[unrelated_identity])
            .await
            .unwrap(),
        [false]
    );
    let identities = [plaintext.as_slice(), secret.as_slice()]
        .map(|bytes| TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap());
    assert_eq!(
        destination.store().has(&identities).await.unwrap(),
        [false, false]
    );
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            request(target(plaintext, None)),
        )
        .await
        .unwrap();
    let snapshot = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), published.commit);
    assert_eq!(
        destination
            .guard()
            .read_content(
                &snapshot,
                b"/file",
                ContentRef::Inline(identities[0].terrane_v1_digest().unwrap()),
                plaintext.len() as u64
            )
            .await
            .unwrap(),
        plaintext
    );
    assert_eq!(
        destination.store().has(&identities[1..]).await.unwrap(),
        [false]
    );
}
