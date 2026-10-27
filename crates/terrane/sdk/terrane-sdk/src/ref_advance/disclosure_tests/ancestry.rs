//! Checks trust selectors against the actual public introduction and ancestry.

use super::*;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use terrane_format::provenance::{Preset, Selector, TrustContext, VerifiedHistory};

fn file_tree(plaintext: &[u8], private: bool) -> Tree<'static> {
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
                attrs: Vec::new(),
                attrs_present: false,
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

fn signed_by(key: &[u8; 32], accepted: bool) -> Selector {
    let key = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut bytes = Vec::new();
    if accepted {
        terrane_format::cbor::write_array(&mut bytes, 2);
        terrane_format::cbor::write_text(&mut bytes, "accepted-by");
    }
    terrane_format::cbor::write_array(&mut bytes, 2);
    terrane_format::cbor::write_text(&mut bytes, "signed-by-key");
    terrane_format::cbor::write_text(&mut bytes, &key);
    Selector::decode(&bytes).unwrap()
}

fn check_selectors(
    history: &VerifiedHistory,
    view: [u8; 32],
    private_key: &[u8; 32],
    public_key: &[u8; 32],
) {
    for (baseline, expected) in [("private-baseline", false), ("public-baseline", true)] {
        let strict = TrustContext::new(
            history,
            view,
            Selector::preset(Preset::Strict),
            "public",
            Some(baseline),
        )
        .unwrap();
        assert_eq!(strict.accepts_path(b"file"), expected);
    }
    for (key, expected) in [(private_key, false), (public_key, true)] {
        let direct =
            TrustContext::new(history, view, signed_by(key, false), "public", None).unwrap();
        assert_eq!(direct.accepts_path(b"file"), expected);
    }
}

/// Keeps private authority claims behind the checked public introduction boundary.
///
/// # Panics
/// Panics if genuine setup fails, private claims satisfy public selectors, public
/// ancestry loses its introducing commit, or source-erased reopening changes trust.
pub(super) async fn check_public_selectors() {
    let (source, authority, credentials) = independent_factory_claims(
        "private:writer",
        terrane_format::refs::PrincipalKind::Human,
        vec!["private-baseline".into()],
    )
    .await;
    let (destination, destination_authority, _) = independent_factory_claims(
        "public",
        terrane_format::refs::PrincipalKind::Human,
        vec!["public-baseline".into()],
    )
    .await;
    let reference = "refs/heads/_/main";
    let plaintext = b"public trust never borrows the attested private introduction";
    let private_tree = file_tree(plaintext, true);
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &private_tree);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let mut source_session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    let private_snapshot = source
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let private_key = private_snapshot.commit.signing_public_key();
    let strict_private = TrustContext::new(
        &private_snapshot.history,
        source_head.commit,
        Selector::preset(Preset::Strict),
        "private:writer",
        Some("private-baseline"),
    )
    .unwrap();
    assert!(strict_private.accepts_path(b"file"));

    let public_tree = file_tree(plaintext, false);
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &public_tree);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: source_head.commit,
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
    let public_key = public_snapshot.commit.signing_public_key();
    assert_ne!(private_key, public_key);
    assert!(
        public_snapshot
            .history
            .commit(&source_head.commit)
            .is_none()
    );
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
    check_selectors(
        &public_snapshot.history,
        published.commit,
        &private_key,
        &public_key,
    );

    let retained = public_snapshot
        .evidence
        .tree(public_snapshot.evidence.root, 262144)
        .unwrap();
    let staged =
        materialization::stage_tree(request_file(vec![published.commit], plaintext), &retained);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let descendant = destination.advance(&mut target, proposal).await.unwrap();
    let checked = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(descendant.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        published.commit
    );
    let walk = checked.history.provenance_walk(&location).unwrap();
    assert!(
        walk.iter()
            .any(|entry| entry.identity() == published.commit)
    );
    assert!(
        walk.iter()
            .all(|entry| entry.identity() != source_head.commit)
    );
    assert_eq!(checked.commit.commit().parents, vec![published.commit]);
    check_selectors(
        &checked.history,
        descendant.commit,
        &private_key,
        &public_key,
    );
    for (key, expected) in [(&private_key, false), (&public_key, true)] {
        let accepted = TrustContext::new(
            &checked.history,
            descendant.commit,
            signed_by(key, true),
            "public",
            None,
        )
        .unwrap();
        assert_eq!(accepted.accepts_path(b"file"), expected);
    }

    let source_root = source.store().root().to_owned();
    let control = source_root.with_file_name(format!(
        "{}-original-control",
        source_root.file_name().unwrap().to_string_lossy()
    ));
    let destination_root = destination.store().root().to_owned();
    let destination_config = destination.guard().config().clone();
    let private_graph = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &source_head.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private_tree.root_identity())
            .unwrap(),
    ];
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );
    drop(strict_private);
    drop(checked);
    drop(retained);
    drop(public_snapshot);
    drop(private_snapshot);
    drop(source_session);
    drop(target);
    drop(source);
    drop(authority);
    for path in [source_root, control, credentials] {
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
    assert_eq!(checked.commit.identity(), descendant.commit);
    assert!(checked.history.commit(&source_head.commit).is_none());
    check_selectors(
        &checked.history,
        descendant.commit,
        &private_key,
        &public_key,
    );
    let (location, _) = checked.history.locate(descendant.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        published.commit
    );
    let EntryKind::File { content, size, .. } = checked.history.entry(&location).unwrap().kind
    else {
        panic!("public selector file changed kind")
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
