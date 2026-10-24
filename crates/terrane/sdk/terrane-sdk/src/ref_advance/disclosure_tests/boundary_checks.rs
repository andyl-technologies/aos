//! Exercises malformed complete native disclosure candidates before transfer.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::selected_bridge::native_guard::disclosure::{
    CertificateMutation, corrupt_next_certificate,
};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};

/// Refuses complete signed-candidate mutations before transferring payloads.
///
/// # Panics
/// Panics if genuine fixture setup fails, a mutation never reaches actual source
/// signing, a malformed candidate publishes, or the unchanged candidate refuses.
pub(super) async fn reject_signed_mutations() {
    let (source, source_authority, _) = independent_factory("public").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"native complete certificate mutation witness";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let mut source_session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), plaintext);
    let mut authored = source_authority.commit_request(staged.commit, "sdk".into());
    authored.uploads = staged.uploads;
    let source_head = source.advance(&mut source_session, authored).await.unwrap();
    let mut destination_session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();

    // Every variant reaches real dedicated source signing before corruption.
    // The destination then signs the altered complete candidate with its genuine
    // key; rejection cannot be explained by a bad outer destination signature.
    for mutation in [
        CertificateMutation::Message,
        CertificateMutation::Timestamp,
        CertificateMutation::ReceiptPath,
        CertificateMutation::SourceCommit,
        CertificateMutation::SourceRoot,
        CertificateMutation::SourcePath,
        CertificateMutation::SourceDomain,
        CertificateMutation::Signature,
        CertificateMutation::AttributeOrigin,
    ] {
        let staged = request_file(Vec::new(), plaintext);
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        let witness = corrupt_next_certificate(destination.store().root(), mutation).unwrap();
        let result = destination
            .advance_disclosure(
                source.guard(),
                &mut destination_session,
                DisclosureCommitRequest {
                    proposal,
                    selections: vec![DisclosureCommitSelection {
                        source_reference: reference.into(),
                        source_commit: source_head.commit,
                        source_path: b"/file".to_vec(),
                        source_token: source_authority.token().to_vec(),
                        destination_path: b"/file".to_vec(),
                    }],
                },
            )
            .await;
        assert!(
            witness.applied(),
            "mutation did not reach genuine signing: {mutation:?}: {result:?}"
        );
        assert!(
            matches!(result, Err(AdvanceError::Store(error))
            if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest))),
            "complete candidate must reject {mutation:?}"
        );
        assert!(destination_session.record().is_none());
        assert!(
            destination
                .store()
                .ref_get(reference)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            destination
                .store()
                .has(std::slice::from_ref(&identity))
                .await
                .unwrap(),
            vec![false]
        );
    }

    // A different canonical declared size changes the content projection even
    // though its plaintext identity and both current authorizations are valid.
    let mut staged = request_file(Vec::new(), plaintext);
    let minimum = destination.guard().config().min_chunk_size;
    let (root, nodes) = {
        let evidence = crate::guard::TreeEvidence::load_tree(
            destination.store(),
            staged.commit.tree,
            &staged.uploads,
            minimum,
        )
        .await
        .unwrap();
        let tree = evidence.tree(staged.commit.tree, minimum).unwrap();
        let mut entries = tree
            .iter()
            .map(|item| LeafItem {
                key: item.key.clone(),
                entry: item.entry.clone(),
            })
            .collect::<Vec<_>>();
        let EntryKind::File { size, .. } = &mut entries[0].entry.kind else {
            panic!("expected genuine source file projection")
        };
        *size += 1;
        let edited = Tree::build(
            entries,
            tree.props().map(<[_]>::to_vec),
            minimum,
            TreeUse::Ordinary,
        )
        .unwrap();
        (
            edited.root_identity(),
            edited
                .nodes()
                .map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                })
                .collect::<Vec<_>>(),
        )
    };
    staged.commit.tree = root;
    staged.uploads.retain(|upload| {
        !matches!(
            upload,
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    staged.uploads.extend(nodes);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let result = destination
        .advance_disclosure(
            source.guard(),
            &mut destination_session,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await;
    assert!(matches!(result, Err(AdvanceError::Store(error))
        if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest))));
    assert!(destination_session.record().is_none());
    assert!(
        destination
            .store()
            .ref_get(reference)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap(),
        vec![false]
    );

    // The exact unmodified request remains publishable after every refusal.
    let staged = request_file(Vec::new(), plaintext);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let accepted = destination
        .advance_disclosure(
            source.guard(),
            &mut destination_session,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(destination_session.record(), Some(&accepted));
    assert_eq!(
        destination.store().ref_get(reference).await.unwrap(),
        Some(accepted)
    );
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap(),
        vec![true]
    );
}
