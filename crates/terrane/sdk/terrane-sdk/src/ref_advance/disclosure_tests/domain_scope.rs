//! Checks actual reference order and authority scope before existing-blob deduplication.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{RefStore, StoreErrorKind};
use terrane_format::auth::{Attenuation, Caveat, Token, public_key_from_secret};

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

fn restrict_domain(
    token: &[u8],
    secret: &[u8; 32],
    key: &terrane_format::auth::IssuerKey,
    domain: &str,
) -> Vec<u8> {
    let narrowed = Token::decode(token)
        .unwrap()
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Domain(domain.into())],
                ..Attenuation::default()
            },
            secret,
            public_key_from_secret(secret),
        )
        .unwrap()
        .encode();
    Token::decode(&narrowed)
        .unwrap()
        .verify(std::slice::from_ref(key), 0)
        .unwrap();
    narrowed
}

/// Requires independently current scope even when identical public bytes already exist.
///
/// # Panics
/// Panics if genuine setup fails, existing blobs bypass domain checks, an illegal
/// physical reference is accepted, or a valid scoped disclosure loses its content.
pub(super) async fn preserve_domain_scope() {
    let (public_source, public_authority, _) = independent_factory("public").await;
    let (private_source, private_authority, _) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let plaintext = b"identical plaintext does not merge source and destination authority";
    let public_tree = file_tree(plaintext, false);
    let private_tree = file_tree(plaintext, true);
    assert_ne!(public_tree.root_identity(), private_tree.root_identity());
    let mut public_session = public_source
        .begin(reference, public_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &public_tree);
    let mut proposal = public_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let public_head = public_source
        .advance(&mut public_session, proposal)
        .await
        .unwrap();
    let mut private_session = private_source
        .begin(reference, private_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &private_tree);
    let mut proposal = private_authority.commit_request(staged.commit, "sdk".into());
    let private_secret = proposal.terminal_secret;
    proposal.uploads = staged.uploads;
    let private_head = private_source
        .advance(&mut private_session, proposal)
        .await
        .unwrap();
    let selection = |commit, token| {
        vec![DisclosureCommitSelection {
            source_reference: reference.into(),
            source_commit: commit,
            source_path: b"/file".to_vec(),
            source_token: token,
            destination_path: b"/file".to_vec(),
        }]
    };
    let mut target = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = materialization::stage_tree(request_file(Vec::new(), plaintext), &public_tree);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let baseline = destination
        .advance_disclosure(
            public_source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: selection(public_head.commit, public_authority.token().to_vec()),
            },
        )
        .await
        .unwrap();
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&chunk))
            .await
            .unwrap(),
        [true]
    );
    let denied_source = restrict_domain(
        private_authority.token(),
        &private_secret,
        private_authority.issuer_key(),
        "public",
    );
    for source_denial in [true, false] {
        let staged = materialization::stage_tree(
            request_file(vec![baseline.commit], plaintext),
            &public_tree,
        );
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        if !source_denial {
            proposal.token = restrict_domain(
                &proposal.token,
                &proposal.terminal_secret,
                destination_authority.issuer_key(),
                "private:writer",
            );
        }
        let rejected = destination
            .advance_disclosure(
                private_source.guard(),
                &mut target,
                DisclosureCommitRequest {
                    proposal,
                    selections: selection(
                        private_head.commit,
                        if source_denial {
                            denied_source.clone()
                        } else {
                            private_authority.token().to_vec()
                        },
                    ),
                },
            )
            .await;
        let verb = if source_denial { "read" } else { "commit" };
        assert!(
            matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: actual, pattern } if *actual == verb && pattern == reference))
        );
        assert_eq!(target.record(), Some(&baseline));
        assert_eq!(
            destination.store().ref_get(reference).await.unwrap(),
            Some(baseline.clone())
        );
        assert_eq!(
            destination
                .store()
                .has(std::slice::from_ref(&chunk))
                .await
                .unwrap(),
            [true]
        );
    }

    let graft = Tree::build(
        vec![LeafItem {
            key: b"closed".to_vec(),
            entry: Entry {
                kind: EntryKind::Tree {
                    root: private_tree.root_identity(),
                    props: None,
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
    let checked = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let layers = checked.evidence.policy_path(b"/file", 262144).unwrap();
    let layers = layers
        .iter()
        .map(
            |(properties, overrides)| terrane_format::properties::RootLayer {
                properties,
                overrides,
            },
        )
        .collect::<Vec<_>>();
    let public_policy = terrane_format::properties::resolve(
        &layers,
        destination.guard().defaults_for(&checked.evidence),
    )
    .unwrap();
    assert_eq!(
        public_policy.domain().unwrap(),
        terrane_format::properties::Domain::Public
    );
    assert!(
        terrane_format::properties::validate_commit(
            &[terrane_format::properties::EntryChange {
                entry: graft.get(b"closed").unwrap(),
                properties: &public_policy,
                reference_domains: &[terrane_format::properties::Domain::Private("writer")],
                graft_properties: None,
            }],
            &[]
        )
        .is_err()
    );
    let mut staged =
        materialization::stage_tree(request_file(vec![baseline.commit], plaintext), &graft);
    staged
        .uploads
        .extend(private_tree.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let rejected = destination.advance(&mut target, proposal).await;
    assert!(
        matches!(rejected, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: "commit", pattern } if pattern == reference))
    );
    assert_eq!(target.record(), Some(&baseline));
    let private_graph = [
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private_tree.root_identity())
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &private_head.commit)
            .unwrap(),
    ];
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );
    assert_eq!(
        destination
            .store()
            .has(&[TERRANE_V1
                .from_digest(IdentityKind::Node, &graft.root_identity())
                .unwrap()])
            .await
            .unwrap(),
        [false]
    );

    let staged =
        materialization::stage_tree(request_file(vec![baseline.commit], plaintext), &public_tree);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let disclosed = destination
        .advance_disclosure(
            private_source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal,
                selections: selection(private_head.commit, private_authority.token().to_vec()),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );
    assert_eq!(destination.store().has(&[chunk]).await.unwrap(), [true]);
    let checked = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(disclosed.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        disclosed.commit
    );
    let entry = checked.history.entry(&location).unwrap();
    let EntryKind::File { content, size, .. } = entry.kind else {
        panic!("scoped disclosure changed file kind")
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
