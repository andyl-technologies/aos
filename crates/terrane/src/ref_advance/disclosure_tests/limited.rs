//! Verifies directory-marker and raw-symlink certificates cannot authorize file data.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, StoreErrorKind};

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

fn limited_tree(private: bool) -> Tree<'static> {
    Tree::build(
        vec![
            LeafItem {
                key: b"link".to_vec(),
                entry: entry(EntryKind::Symlink { target: b"hidden" }),
            },
            LeafItem {
                key: b"marker".to_vec(),
                entry: entry(EntryKind::Directory { mode: 0o755 }),
            },
        ],
        super::materialization::properties(private),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
}

/// Certifies limited entries while refusing to expand either into a file claim.
///
/// # Panics
/// Panics if genuine setup or publication fails, either mismatched file claim
/// succeeds, private content transfers, or raw marker/symlink values change.
pub(super) async fn certify_limited_entries() {
    let (source, authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let secret = b"the symlink target remains private and uncertified";
    let secret_identity = TERRANE_V1.calculate(IdentityKind::Chunk, secret).unwrap();
    let limited = limited_tree(true);
    let mut items = limited.iter().cloned().collect::<Vec<_>>();
    items.push(LeafItem {
        key: b"hidden".to_vec(),
        entry: entry(EntryKind::File {
            mode: 0o600,
            size: secret.len() as u64,
            content: ContentRef::Inline(secret_identity.terrane_v1_digest().unwrap()),
            link_id: None,
        }),
    });
    items.sort_by(|left, right| left.key.cmp(&right.key));
    let private = Tree::build(
        items,
        super::materialization::properties(true),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let staged = super::materialization::stage_tree(request_file(Vec::new(), secret), &private);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let mut source_session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();

    for path in [b"marker".as_slice(), b"link".as_slice()] {
        let file = Tree::build(
            vec![LeafItem {
                key: path.to_vec(),
                entry: entry(EntryKind::File {
                    mode: 0o644,
                    size: secret.len() as u64,
                    content: ContentRef::Inline(secret_identity.terrane_v1_digest().unwrap()),
                    link_id: None,
                }),
            }],
            super::materialization::properties(false),
            262144,
            TreeUse::Ordinary,
        )
        .unwrap();
        let staged = super::materialization::stage_tree(request_file(Vec::new(), secret), &file);
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        let absolute = [b"/".as_slice(), path].concat();
        let rejected = destination
            .advance_disclosure(
                source.guard(),
                &mut target,
                DisclosureCommitRequest {
                    proposal,
                    selections: vec![DisclosureCommitSelection {
                        source_reference: reference.into(),
                        source_commit: source_head.commit,
                        source_path: absolute.clone(),
                        source_token: authority.token().to_vec(),
                        destination_path: absolute,
                    }],
                },
            )
            .await;
        assert!(
            matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
        );
        assert!(target.record().is_none());
        assert_eq!(
            destination
                .store()
                .has(std::slice::from_ref(&secret_identity))
                .await
                .unwrap(),
            [false]
        );
    }

    let public = limited_tree(false);
    let staged = super::materialization::stage_tree(request(Vec::new()), &public);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: [b"/marker".as_slice(), b"/link".as_slice()]
                    .into_iter()
                    .map(|path| DisclosureCommitSelection {
                        source_reference: reference.into(),
                        source_commit: source_head.commit,
                        source_path: path.to_vec(),
                        source_token: authority.token().to_vec(),
                        destination_path: path.to_vec(),
                    })
                    .collect(),
            },
        )
        .await
        .unwrap();
    let snapshot = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/link", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot.history.locate(published.commit, b"link").unwrap();
    assert!(matches!(
        snapshot.history.entry(&location).unwrap().kind,
        EntryKind::Symlink { target: b"hidden" }
    ));
    let (location, _) = snapshot
        .history
        .locate(published.commit, b"marker")
        .unwrap();
    assert!(matches!(
        snapshot.history.entry(&location).unwrap().kind,
        EntryKind::Directory { .. }
    ));
    let read = destination
        .guard()
        .read_content(
            &snapshot,
            b"/link",
            ContentRef::Inline(secret_identity.terrane_v1_digest().unwrap()),
            secret.len() as u64,
        )
        .await;
    assert!(
        matches!(read, Err(error) if matches!(error.kind(), StoreErrorKind::Denied { verb: "read", pattern } if pattern == reference))
    );
    let private_root = TERRANE_V1
        .from_digest(IdentityKind::Node, &private.root_identity())
        .unwrap();
    assert_eq!(
        destination
            .store()
            .has(&[secret_identity, private_root])
            .await
            .unwrap(),
        [false, false]
    );
}
