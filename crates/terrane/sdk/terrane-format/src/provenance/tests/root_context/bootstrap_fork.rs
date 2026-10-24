//! Checks independent original bootstrap authority for unchanged-root publication.

use super::*;

const SOURCE: &str = "refs/heads/main";
const DESTINATION: &str = "refs/heads/fork";
const PRINCIPAL: &str = "build/baseline";
const SOURCE_OWNER: &str = "source-original-authority";
const DESTINATION_OWNER: &str = "destination-original-authority";
const SOURCE_ACL: &[(&str, u8)] = &[(PRINCIPAL, 16)];
const COMMIT_ACL: &[(&str, u8)] = &[(PRINCIPAL, 4)];

struct ForkFixture {
    history: VerifiedHistory,
    parent: VerifiedCommit,
    root_bytes: Vec<u8>,
}

fn authored(mut commit: Commit, reference: &str, epoch: u64, verbs: u8) -> VerifiedCommit {
    let original = Token::decode(commit.provenance.embedded_token.as_deref().unwrap()).unwrap();
    let mut authority = original
        .verify(&issuer_keys(), commit.timestamp)
        .unwrap()
        .authority()
        .clone();
    authority.grants = vec![Grant::new(reference.to_string(), Verbs::new(verbs).unwrap()).unwrap()];
    let token = Token::issue(
        authority,
        &[7; 32],
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    commit.provenance.embedded_token = Some(token.encode());
    commit.provenance.writer_epoch = epoch;
    commit.signature = None;

    with_request(|base| {
        let request = Request {
            reference: reference.as_bytes(),
            now: commit.timestamp,
            roots: &[RequestRoot {
                path: b"/",
                domain: PUBLIC,
            }],
            epochs: &[(reference, epoch)],
            ..*base
        };
        commit.profile_pair.commit_context = Some(CommitContext::from_request(&request).unwrap());
        sign_authored(commit, &[9; 32], &issuer_keys(), &request, epoch).unwrap()
    })
}

fn policy<'a>(
    authority: &'a str,
    reference: &'a str,
    epoch: u64,
    acl: &'a [(&'a str, u8)],
) -> OriginalBootstrapPolicy<'a> {
    OriginalBootstrapPolicy {
        authority,
        reference,
        writer_epoch: epoch,
        acl,
    }
}

impl ForkFixture {
    fn new() -> Self {
        Self::with_root_acl(SOURCE_ACL)
    }

    fn with_root_acl(root_acl: &[(&str, u8)]) -> Self {
        let (child, child_bytes) = domain_tree(vec![item(b"file", entry(b"inherited"))], PUBLIC);
        let mut acl = Vec::new();
        crate::cbor::write_array(&mut acl, root_acl.len());
        for (name, verbs) in root_acl {
            crate::cbor::write_array(&mut acl, 2);
            crate::cbor::write_text(&mut acl, name);
            crate::cbor::write_uint(&mut acl, u64::from(*verbs));
        }
        let mut domain = Vec::new();
        crate::cbor::write_text(&mut domain, PUBLIC);
        let (root, root_bytes) = tree(
            vec![item(b"child", graft(child))],
            Some(vec![
                Property {
                    name: "acl",
                    value: &acl,
                },
                Property {
                    name: "domain",
                    value: &domain,
                },
            ]),
        );
        let mut commit = unsigned_commit();
        commit.tree = root;
        let parent = authored(commit, SOURCE, 4, 4);
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history.insert_tree(child, &[(child, child_bytes)]).unwrap();
        history
            .insert_tree(root, &[(root, root_bytes.clone())])
            .unwrap();
        history.insert_commit(parent.clone()).unwrap();
        verify_root_context_with_bootstrap(
            &mut history,
            parent.identity(),
            defaults(),
            SOURCE_OWNER,
            policy(SOURCE_OWNER, SOURCE, 4, SOURCE_ACL),
        )
        .unwrap();
        Self {
            history,
            parent,
            root_bytes,
        }
    }

    fn copied(&mut self, reference: &str, epoch: u64, verbs: u8) -> VerifiedCommit {
        let mut commit = self.parent.commit().clone();
        commit.message = "Copy unchanged root under original authority".to_string();
        crate::algebra::fork(commit.tree, self.parent.identity(), 1).bind_commit(&mut commit);
        let copied = authored(commit, reference, epoch, verbs);
        self.history.insert_commit(copied.clone()).unwrap();
        copied
    }
}

#[test]
fn prov_commit_bootstrap_copied_fork_widening_requires_original_destination_admin() {
    for verbs in [4, 16] {
        let mut fixture = ForkFixture::new();
        let copied = fixture.copied(DESTINATION, 1, verbs);
        let bytes = copied.commit().encode().unwrap();
        let plan = derive_root_changes(&fixture.history, copied.commit(), defaults()).unwrap();
        assert!(!plan.fresh());
        assert!(plan.affected().is_empty());

        let checked = verify_root_context_with_bootstrap(
            &mut fixture.history,
            copied.identity(),
            defaults(),
            DESTINATION_OWNER,
            policy(DESTINATION_OWNER, DESTINATION, 1, COMMIT_ACL),
        );
        assert_eq!(checked.is_ok(), verbs == 16);
        if let Ok(scope) = checked {
            assert!(!scope.changes().fresh());
            assert!(scope.changes().affected().is_empty());
            assert_eq!(scope.changes().required_admin().len(), 1);
            assert_eq!(scope.changes().required_admin()[0].path(), b"/");
            assert_eq!(
                scope.changes().required_admin()[0].side(),
                RootSide::Candidate
            );
        } else {
            assert!(
                fixture
                    .history
                    .require_verified_context(copied.identity())
                    .is_err()
            );
        }
        assert_eq!(copied.commit().encode().unwrap(), bytes);
    }
}

#[test]
fn prov_commit_bootstrap_copied_fork_retaining_or_narrowing_needs_only_original_commit() {
    for (candidate_acl, baseline_acl) in [
        (SOURCE_ACL, SOURCE_ACL),
        (SOURCE_ACL, &[(PRINCIPAL, 31_u8)] as &[(&str, u8)]),
        (COMMIT_ACL, SOURCE_ACL),
    ] {
        let mut fixture = ForkFixture::with_root_acl(candidate_acl);
        let copied = fixture.copied(DESTINATION, 1, 4);
        let scope = verify_root_context_with_bootstrap(
            &mut fixture.history,
            copied.identity(),
            defaults(),
            DESTINATION_OWNER,
            policy(DESTINATION_OWNER, DESTINATION, 1, baseline_acl),
        )
        .unwrap();
        assert!(!scope.changes().fresh());
        assert!(scope.changes().affected().is_empty());
        assert!(scope.changes().required_admin().is_empty());
    }
}

#[test]
fn prov_commit_bootstrap_legacy_parent_requires_independent_original_candidate_baseline() {
    for reference in [SOURCE, DESTINATION] {
        for (verbs, candidate_acl, baseline_acl, accepted) in [
            (4, SOURCE_ACL, COMMIT_ACL, false),
            (16, SOURCE_ACL, COMMIT_ACL, true),
            (4, SOURCE_ACL, SOURCE_ACL, true),
            (4, SOURCE_ACL, &[(PRINCIPAL, 31_u8)] as &[(&str, u8)], true),
            (4, COMMIT_ACL, SOURCE_ACL, true),
        ] {
            let mut fixture = ForkFixture::with_root_acl(candidate_acl);
            let mut legacy = fixture.parent.commit().clone();
            legacy.profile_pair.commit_context = None;
            legacy.signature = None;
            fixture.parent = with_request(|base| {
                let request = Request {
                    reference: SOURCE.as_bytes(),
                    roots: &[RequestRoot {
                        path: b"/",
                        domain: PUBLIC,
                    }],
                    ..*base
                };
                let signed = sign(legacy, &[9; 32], &issuer_keys(), &request, 4).unwrap();
                let decoded = Commit::decode(&signed.commit().encode().unwrap()).unwrap();
                verify(&decoded, &issuer_keys(), &request, 4).unwrap()
            });
            let original_bytes = fixture.parent.commit().encode().unwrap();
            assert!(
                fixture
                    .parent
                    .commit()
                    .profile_pair
                    .commit_context
                    .is_none()
            );
            fixture
                .history
                .insert_commit(fixture.parent.clone())
                .unwrap();
            assert!(
                fixture
                    .history
                    .require_verified_context(fixture.parent.identity())
                    .is_ok()
            );

            let copied = fixture.copied(reference, 1, verbs);
            assert!(copied.commit().profile_pair.commit_context.is_some());
            assert!(
                verify_root_context(&mut fixture.history, copied.identity(), defaults()).is_err()
            );
            let checked = verify_root_context_with_bootstrap(
                &mut fixture.history,
                copied.identity(),
                defaults(),
                DESTINATION_OWNER,
                policy(DESTINATION_OWNER, reference, 1, baseline_acl),
            );
            assert_eq!(checked.is_ok(), accepted);
            if let Ok(scope) = checked {
                assert!(!scope.changes().fresh());
                assert!(scope.changes().affected().is_empty());
                assert_eq!(
                    scope.changes().required_admin().is_empty(),
                    baseline_acl != COMMIT_ACL
                );
            }
            assert_eq!(fixture.parent.commit().encode().unwrap(), original_bytes);
        }
    }
}

#[test]
fn prov_commit_bootstrap_copied_fork_rejects_missing_or_mismatched_original_baseline() {
    let mut fixture = ForkFixture::new();
    let copied = fixture.copied(DESTINATION, 1, 16);
    assert!(verify_root_context(&mut fixture.history, copied.identity(), defaults()).is_err());

    for original in [
        policy(SOURCE_OWNER, DESTINATION, 1, SOURCE_ACL),
        policy(DESTINATION_OWNER, SOURCE, 1, SOURCE_ACL),
        policy(DESTINATION_OWNER, DESTINATION, 2, SOURCE_ACL),
    ] {
        assert!(
            verify_root_context_with_bootstrap(
                &mut fixture.history,
                copied.identity(),
                defaults(),
                DESTINATION_OWNER,
                original,
            )
            .is_err()
        );
        assert!(
            fixture
                .history
                .require_verified_context(copied.identity())
                .is_err()
        );
    }
}

#[test]
fn prov_commit_bootstrap_later_admin_does_not_repair_original_copied_fork_authority() {
    let mut fixture = ForkFixture::new();
    let original = fixture.copied(DESTINATION, 1, 4);
    let bytes = original.commit().encode().unwrap();
    let mut later = fixture.parent.commit().clone();
    later.timestamp = 150;
    later.provenance.observed_at = 150;
    crate::algebra::fork(later.tree, fixture.parent.identity(), 1).bind_commit(&mut later);
    let later = authored(later, DESTINATION, 2, 16);
    fixture.history.insert_commit(later.clone()).unwrap();
    verify_root_context_with_bootstrap(
        &mut fixture.history,
        later.identity(),
        defaults(),
        DESTINATION_OWNER,
        policy(DESTINATION_OWNER, DESTINATION, 2, COMMIT_ACL),
    )
    .unwrap();

    assert!(
        verify_root_context_with_bootstrap(
            &mut fixture.history,
            original.identity(),
            defaults(),
            DESTINATION_OWNER,
            policy(DESTINATION_OWNER, DESTINATION, 1, COMMIT_ACL),
        )
        .is_err()
    );
    assert_eq!(original.commit().encode().unwrap(), bytes);
    assert!(
        fixture
            .history
            .require_verified_context(original.identity())
            .is_err()
    );
}

#[test]
fn prov_commit_bootstrap_same_ref_different_original_owner_requires_independent_comparison() {
    for verbs in [4, 16] {
        let mut fixture = ForkFixture::new();
        let copied = fixture.copied(SOURCE, 5, verbs);
        let checked = verify_root_context_with_bootstrap(
            &mut fixture.history,
            copied.identity(),
            defaults(),
            DESTINATION_OWNER,
            policy(DESTINATION_OWNER, SOURCE, 5, COMMIT_ACL),
        );
        assert_eq!(checked.is_ok(), verbs == 16);
    }
}

#[test]
fn prov_commit_bootstrap_explicit_same_ref_continuity_requires_parent_original_evidence() {
    let mut fixture = ForkFixture::new();
    let intermediate = fixture.copied(SOURCE, 5, 4);
    verify_root_context(&mut fixture.history, intermediate.identity(), defaults()).unwrap();
    let mut commit = intermediate.commit().clone();
    commit.message = "Continue checked ordinary authoring".to_string();
    crate::algebra::fork(commit.tree, intermediate.identity(), 2).bind_commit(&mut commit);
    let continuation = authored(commit, SOURCE, 6, 4);
    fixture.history.insert_commit(continuation.clone()).unwrap();
    assert!(
        verify_root_context_with_bootstrap(
            &mut fixture.history,
            continuation.identity(),
            defaults(),
            SOURCE_OWNER,
            policy(SOURCE_OWNER, SOURCE, 6, SOURCE_ACL),
        )
        .is_err()
    );

    verify_root_context_with_bootstrap(
        &mut fixture.history,
        intermediate.identity(),
        defaults(),
        SOURCE_OWNER,
        policy(SOURCE_OWNER, SOURCE, 5, SOURCE_ACL),
    )
    .unwrap();
    let scope = verify_root_context_with_bootstrap(
        &mut fixture.history,
        continuation.identity(),
        defaults(),
        SOURCE_OWNER,
        policy(SOURCE_OWNER, SOURCE, 6, COMMIT_ACL),
    )
    .unwrap();
    assert!(scope.changes().required_admin().is_empty());
}

#[test]
fn prov_commit_bootstrap_copied_fork_comparison_uses_only_view_root_policy_witness() {
    let fixture = ForkFixture::new();
    let mut bounded = VerifiedHistory::new(MIN_CHUNK);
    bounded
        .insert_tree(
            fixture.parent.commit().tree,
            &[(fixture.parent.commit().tree, fixture.root_bytes)],
        )
        .unwrap();
    bounded.insert_commit(fixture.parent.clone()).unwrap();
    // These opaque annotations were genuinely checked with complete source
    // witnesses above. Only the unchanged descendant bytes are unavailable in
    // this candidate witness set; no decoded record substitutes for the scope.
    bounded.root_scopes = fixture.history.root_scopes.clone();
    bounded.bootstrap_policies = fixture.history.bootstrap_policies.clone();
    let mut commit = fixture.parent.commit().clone();
    crate::algebra::fork(commit.tree, fixture.parent.identity(), 1).bind_commit(&mut commit);
    let copied = authored(commit, DESTINATION, 1, 16);
    bounded.insert_commit(copied.clone()).unwrap();

    let scope = verify_root_context_with_bootstrap(
        &mut bounded,
        copied.identity(),
        defaults(),
        DESTINATION_OWNER,
        policy(DESTINATION_OWNER, DESTINATION, 1, COMMIT_ACL),
    )
    .unwrap();
    assert!(!scope.changes().fresh());
    assert!(scope.changes().affected().is_empty());
    assert_eq!(scope.changes().required_admin().len(), 1);
}
