//! Certifies a genuinely resolved private conflict through paired native publication.

use super::*;
use crate::ref_advance::{
    AdvanceError, CommitRequest, DisclosureCommitRequest, DisclosureCommitSelection,
};
use crate::store::{InvalidReason, StoreErrorKind};
use terrane_format::refs::MergePolicy;

fn file_request(parents: Vec<[u8; 32]>, plaintext: &[u8], private: bool) -> CommitRequest {
    let staged = request_file(parents, plaintext);
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(content.terrane_v1_digest().unwrap()),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        super::materialization::properties(private),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    super::materialization::stage_tree(staged, &tree)
}

/// Certifies the actual selected file after canonical native conflict resolution.
///
/// # Panics
/// Panics if genuine branching or merge fails, raw conflict projection succeeds,
/// resolution chooses another producer, or destination content differs.
pub(super) async fn certify_resolved_file() {
    let (source, authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let branch = "refs/heads/_/incoming";
    let mut main = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = file_request(Vec::new(), b"base", true);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let base = source.advance(&mut main, proposal).await.unwrap();
    let mut signing = authority.commit_request(request(Vec::new()).commit, "sdk".into());
    signing.uploads.clear();
    let fork = source.fork(reference, branch, signing).await.unwrap();
    let mut incoming = source
        .begin(branch, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = file_request(vec![base.commit], b"ours", true);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    source.advance(&mut main, proposal).await.unwrap();
    let staged = file_request(vec![fork.commit], b"theirs", true);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let theirs = source.advance(&mut incoming, proposal).await.unwrap();
    let mut signing = authority.commit_request(request(Vec::new()).commit, "sdk".into());
    signing.uploads.clear();
    let conflict = source
        .merge(&mut main, branch, signing, &[MergePolicy::KeepConflict])
        .await
        .unwrap();
    let snapshot = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot.history.locate(conflict.commit, b"file").unwrap();
    assert!(matches!(
        snapshot.history.entry(&location).unwrap().kind,
        EntryKind::Conflict { .. }
    ));

    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = file_request(Vec::new(), b"chosen canonical resolution", false);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let rejected = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: conflict.commit,
                    source_path: b"/file".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))
    );
    assert!(target.record().is_none());

    let plaintext = b"chosen canonical resolution";
    let staged = file_request(vec![theirs.commit], plaintext, true);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let selected = source.advance(&mut incoming, proposal).await.unwrap();
    let mut signing = authority.commit_request(request(Vec::new()).commit, "sdk".into());
    signing.uploads.clear();
    let resolved = source
        .merge(&mut main, branch, signing, &[MergePolicy::PreferTheirs])
        .await
        .unwrap();
    let checked = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(resolved.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        selected.commit
    );
    assert!(matches!(
        checked.history.entry(&location).unwrap().kind,
        EntryKind::File { .. }
    ));
    let staged = file_request(Vec::new(), plaintext, false);
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
                    source_commit: resolved.commit,
                    source_path: b"/file".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    let snapshot = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), published.commit);
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    assert_eq!(
        destination
            .guard()
            .read_content(
                &snapshot,
                b"/file",
                ContentRef::Inline(identity.terrane_v1_digest().unwrap()),
                plaintext.len() as u64
            )
            .await
            .unwrap(),
        plaintext
    );
}
