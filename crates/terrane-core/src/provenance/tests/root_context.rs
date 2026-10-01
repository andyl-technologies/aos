//! Exercises canonical root changes, original grants and historical policy sides.

use super::*;
use crate::{
    auth::{Attenuation, Caveat, RequestRoot},
    identity::Digest,
    properties::Defaults,
    refs::CommitContext,
    tree_format::{Entry, EntryKind, LeafItem, Property},
};

const PUBLIC: &str = "public";

mod bootstrap;

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "test",
        private_domain: "private:untrusted-routing-label",
        home: "west",
    }
}

fn domain_tree(items: Vec<LeafItem<'_>>, domain: &str) -> (Digest, Vec<u8>) {
    let mut bytes = Vec::new();
    crate::cbor::write_text(&mut bytes, domain);
    tree(
        items,
        Some(vec![Property {
            name: "domain",
            value: &bytes,
        }]),
    )
}

fn graft(root: Digest) -> Entry<'static> {
    let mut entry = entry(b"");
    entry.kind = EntryKind::Tree { root, props: None };
    entry
}

fn signed(
    commit: Commit,
    claims: &[RequestRoot<'_>],
    grant: &str,
    caveats: Vec<Caveat>,
) -> VerifiedCommit {
    signed_grants(
        commit,
        claims,
        vec![Grant::new(grant.to_string(), Verbs::new(4).unwrap()).unwrap()],
        caveats,
    )
}

fn signed_grants(
    mut commit: Commit,
    claims: &[RequestRoot<'_>],
    grants: Vec<Grant>,
    caveats: Vec<Caveat>,
) -> VerifiedCommit {
    let original = Token::decode(commit.provenance.embedded_token.as_deref().unwrap()).unwrap();
    let mut authority = original
        .verify(&issuer_keys(), 100)
        .unwrap()
        .authority()
        .clone();
    authority.grants = grants;
    let token = Token::issue(
        authority,
        &[7; 32],
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let (token, secret) = if caveats.is_empty() {
        (token, [9; 32])
    } else {
        (
            token
                .attenuate(
                    Attenuation {
                        caveats,
                        ..Default::default()
                    },
                    &[9; 32],
                    SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
                )
                .unwrap(),
            [10; 32],
        )
    };
    commit.provenance.embedded_token = Some(token.encode());
    with_request(|request| {
        let request = Request {
            roots: claims,
            ..*request
        };
        commit.profile_pair.commit_context = Some(CommitContext::from_request(&request).unwrap());
        sign_authored(commit, &secret, &issuer_keys(), &request, 4).unwrap()
    })
}

struct Fixture {
    history: VerifiedHistory,
    parent: VerifiedCommit,
    docs: Digest,
    secret: Digest,
}

fn fixture() -> Fixture {
    let (docs, docs_bytes) = domain_tree(vec![item(b"file", entry(b"old"))], PUBLIC);
    let (secret, secret_bytes) = domain_tree(vec![item(b"file", entry(b"secret"))], PUBLIC);
    let (root, root_bytes) = domain_tree(
        vec![item(b"docs", graft(docs)), item(b"secret", graft(secret))],
        PUBLIC,
    );
    let mut commit = unsigned_commit();
    commit.tree = root;
    let parent = signed(
        commit,
        &[RequestRoot {
            path: b"/",
            domain: PUBLIC,
        }],
        "refs/heads/main",
        vec![],
    );
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    for (root, bytes) in [
        (docs, docs_bytes),
        (secret, secret_bytes),
        (root, root_bytes),
    ] {
        history.insert_tree(root, &[(root, bytes)]).unwrap();
    }
    history.insert_commit(parent.clone()).unwrap();
    verify_fixture_scope(&mut history, parent.identity(), defaults()).unwrap();
    Fixture {
        history,
        parent,
        docs,
        secret,
    }
}

fn candidate(
    fixture: &mut Fixture,
    docs_value: &'static [u8],
    secret_value: Option<&'static [u8]>,
) -> Commit {
    let (docs, docs_bytes) = domain_tree(vec![item(b"file", entry(docs_value))], PUBLIC);
    fixture
        .history
        .insert_tree(docs, &[(docs, docs_bytes)])
        .unwrap();
    let secret = if let Some(value) = secret_value {
        let (root, bytes) = domain_tree(vec![item(b"file", entry(value))], PUBLIC);
        fixture.history.insert_tree(root, &[(root, bytes)]).unwrap();
        root
    } else {
        fixture.secret
    };
    let (root, root_bytes) = domain_tree(
        vec![item(b"docs", graft(docs)), item(b"secret", graft(secret))],
        PUBLIC,
    );
    fixture
        .history
        .insert_tree(root, &[(root, root_bytes)])
        .unwrap();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![fixture.parent.identity()];
    commit
}

#[test]
fn prov_commit_root_context_child_edit_excludes_digest_only_ancestors_and_siblings() {
    let mut fixture = fixture();
    let commit = candidate(&mut fixture, b"new", None);
    let plan = derive_root_changes(&fixture.history, &commit, defaults()).unwrap();
    assert_eq!(plan.affected().len(), 2);
    assert!(plan.affected().iter().all(|root| root.path() == b"/docs"
        && root.domain() == PUBLIC
        && !root.properties_changed()));
    assert!(
        plan.affected()
            .iter()
            .any(|root| root.side() == RootSide::Previous && root.root() == fixture.docs)
    );
    let signed = signed(
        commit,
        &[RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        }],
        "refs/heads/main:/docs",
        vec![],
    );
    fixture.history.insert_commit(signed.clone()).unwrap();
    assert!(
        TrustContext::new(
            &fixture.history,
            signed.identity(),
            Selector::preset(Preset::Any),
            PUBLIC,
            None
        )
        .is_err()
    );
    let scope = verify_fixture_scope(&mut fixture.history, signed.identity(), defaults()).unwrap();
    assert_eq!(scope.changes(), &plan);
    assert_eq!(scope.claims()[0].path(), b"/docs");
}

#[test]
fn prov_commit_root_context_signature_for_one_child_cannot_cover_changed_sibling() {
    let mut fixture = fixture();
    let commit = candidate(&mut fixture, b"new", Some(b"changed secret"));
    let signed = signed(
        commit,
        &[RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        }],
        "refs/heads/main:/docs",
        vec![],
    );
    fixture.history.insert_commit(signed.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, signed.identity(), defaults()).is_err());
    assert!(
        TrustContext::new(
            &fixture.history,
            signed.identity(),
            Selector::preset(Preset::Any),
            PUBLIC,
            None
        )
        .is_err()
    );
}

#[test]
fn prov_commit_root_context_claim_is_an_actual_root_and_cannot_be_a_file_or_label() {
    let fixture = fixture();
    for claim in [
        RequestRoot {
            path: b"/docs/file",
            domain: PUBLIC,
        },
        RequestRoot {
            path: b"/docs",
            domain: "private:false-label",
        },
        RequestRoot {
            path: b"/missing",
            domain: PUBLIC,
        },
    ] {
        let mut commit = unsigned_commit();
        commit.tree = fixture.parent.commit().tree;
        commit.parents = vec![fixture.parent.identity()];
        let signed = signed(commit, &[claim], "refs/heads/main", vec![]);
        let mut history = fixture.history.clone();
        history.insert_commit(signed.clone()).unwrap();
        assert!(verify_fixture_scope(&mut history, signed.identity(), defaults()).is_err());
    }
}

#[test]
fn prov_commit_root_context_broad_historical_claims_remain_valid_and_caveats_reauthorize_actual_roots()
 {
    let mut fixture = fixture();
    let commit = candidate(&mut fixture, b"new", None);
    let broad = signed(
        commit.clone(),
        &[RequestRoot {
            path: b"/",
            domain: PUBLIC,
        }],
        "refs/heads/main",
        vec![],
    );
    fixture.history.insert_commit(broad.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, broad.identity(), defaults()).is_ok());

    // The signed root claim itself passes this exact-root caveat. The actual
    // changed child does not, so signature authentication alone is insufficient.
    let restricted = signed(
        commit,
        &[RequestRoot {
            path: b"/",
            domain: PUBLIC,
        }],
        "refs/heads/main",
        vec![Caveat::Root("/".to_string())],
    );
    fixture.history.insert_commit(restricted.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, restricted.identity(), defaults()).is_err());
}

#[test]
fn prov_commit_root_context_removed_and_moved_roots_use_prior_policy() {
    let mut fixture = fixture();
    let (root, bytes) = domain_tree(
        vec![
            item(b"moved", graft(fixture.docs)),
            item(b"secret", graft(fixture.secret)),
        ],
        PUBLIC,
    );
    fixture.history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![fixture.parent.identity()];
    let plan = derive_root_changes(&fixture.history, &commit, defaults()).unwrap();
    assert!(
        plan.affected()
            .iter()
            .any(|root| root.path() == b"/docs" && root.side() == RootSide::Previous)
    );
    assert!(
        plan.affected()
            .iter()
            .any(|root| root.path() == b"/moved" && root.side() == RootSide::Candidate)
    );
    assert!(!plan.affected().iter().any(|root| root.path() == b"/secret"));
    let signed = signed(
        commit,
        &[RequestRoot {
            path: b"/",
            domain: PUBLIC,
        }],
        "refs/heads/main",
        vec![],
    );
    fixture.history.insert_commit(signed.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, signed.identity(), defaults()).is_ok());
}

#[test]
fn prov_commit_root_context_domain_change_requires_both_real_policy_sides() {
    let mut fixture = fixture();
    let (docs, docs_bytes) = domain_tree(vec![item(b"file", entry(b"new"))], "private:docs");
    fixture
        .history
        .insert_tree(docs, &[(docs, docs_bytes)])
        .unwrap();
    let (root, bytes) = domain_tree(
        vec![
            item(b"docs", graft(docs)),
            item(b"secret", graft(fixture.secret)),
        ],
        PUBLIC,
    );
    fixture.history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![fixture.parent.identity()];
    let plan = derive_root_changes(&fixture.history, &commit, defaults()).unwrap();
    assert_eq!(plan.affected().len(), 2);
    assert!(
        plan.affected()
            .iter()
            .any(|root| root.domain() == PUBLIC && root.side() == RootSide::Previous)
    );
    assert!(
        plan.affected()
            .iter()
            .any(|root| root.domain() == "private:docs" && root.side() == RootSide::Candidate)
    );
    let claims = [
        RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        },
        RequestRoot {
            path: b"/docs",
            domain: "private:docs",
        },
    ];
    let complete = signed(commit.clone(), &claims, "refs/heads/main:/docs", vec![]);
    fixture.history.insert_commit(complete.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, complete.identity(), defaults()).is_ok());
    let partial = signed(commit, &claims[1..], "refs/heads/main:/docs", vec![]);
    fixture.history.insert_commit(partial.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, partial.identity(), defaults()).is_err());
}

#[test]
fn prov_commit_root_context_initial_publication_requires_actual_main_root_scope() {
    let fixture = fixture();
    let mut commit = unsigned_commit();
    commit.tree = fixture.parent.commit().tree;
    let narrow = signed(
        commit,
        &[RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        }],
        "refs/heads/main:/docs",
        vec![],
    );
    let mut history = fixture.history.clone();
    history.insert_commit(narrow.clone()).unwrap();
    assert!(verify_fixture_scope(&mut history, narrow.identity(), defaults()).is_err());
}

#[test]
fn prov_commit_root_context_copied_tree_retains_original_epoch_and_has_empty_diff() {
    let mut fixture = fixture();
    let mut commit = unsigned_commit();
    commit.tree = fixture.parent.commit().tree;
    commit.parents = vec![fixture.parent.identity()];
    let plan = derive_root_changes(&fixture.history, &commit, defaults()).unwrap();
    assert!(plan.affected().is_empty());
    assert!(!plan.fresh());
    let copied = signed(
        commit,
        &[RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        }],
        "refs/heads/main:/docs",
        vec![Caveat::Epoch("refs/heads/main".to_string(), 4)],
    );
    fixture.history.insert_commit(copied.clone()).unwrap();
    let checked =
        verify_fixture_scope(&mut fixture.history, copied.identity(), defaults()).unwrap();
    assert_eq!(checked.changes(), &plan);
}

#[test]
fn prov_commit_root_context_implicit_owner_is_canonical_and_must_be_preserved() {
    let (old_root, old_bytes) = tree(vec![item(b"file", entry(b"old"))], None);
    let owner = super::super::root_context::canonical_private_domain(old_root).unwrap();
    let mut initial = unsigned_commit();
    initial.tree = old_root;
    let initial = signed(
        initial,
        &[RequestRoot {
            path: b"/",
            domain: &owner,
        }],
        "refs/heads/main",
        vec![],
    );
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(old_root, &[(old_root, old_bytes)])
        .unwrap();
    history.insert_commit(initial.clone()).unwrap();
    verify_fixture_scope(&mut history, initial.identity(), defaults()).unwrap();

    let (new_root, new_bytes) = domain_tree(vec![item(b"file", entry(b"new"))], &owner);
    history
        .insert_tree(new_root, &[(new_root, new_bytes)])
        .unwrap();
    let mut preserved = unsigned_commit();
    preserved.tree = new_root;
    preserved.parents = vec![initial.identity()];
    let plan = derive_root_changes(&history, &preserved, defaults()).unwrap();
    assert_eq!(plan.affected().len(), 2);
    assert!(
        plan.affected()
            .iter()
            .all(|root| root.domain() == owner && !root.properties_changed())
    );
    let preserved = signed(
        preserved,
        &[RequestRoot {
            path: b"/",
            domain: &owner,
        }],
        "refs/heads/main",
        vec![],
    );
    history.insert_commit(preserved.clone()).unwrap();
    verify_fixture_scope(&mut history, preserved.identity(), defaults()).unwrap();

    let (unowned, bytes) = tree(vec![item(b"file", entry(b"new"))], None);
    history.insert_tree(unowned, &[(unowned, bytes)]).unwrap();
    let mut changed = unsigned_commit();
    changed.tree = unowned;
    changed.parents = vec![initial.identity()];
    assert!(derive_root_changes(&history, &changed, defaults()).is_err());
}

#[test]
fn prov_commit_root_context_acl_change_requires_original_admin_on_root_or_ancestor() {
    let mut fixture = fixture();
    let mut public = Vec::new();
    crate::cbor::write_text(&mut public, PUBLIC);
    let acl = b"\x81\x82\x6cbuild/public\x04";
    let (docs, bytes) = tree(
        vec![item(b"file", entry(b"old"))],
        Some(vec![
            Property {
                name: "acl",
                value: acl,
            },
            Property {
                name: "domain",
                value: &public,
            },
        ]),
    );
    fixture.history.insert_tree(docs, &[(docs, bytes)]).unwrap();
    let (root, bytes) = domain_tree(
        vec![
            item(b"docs", graft(docs)),
            item(b"secret", graft(fixture.secret)),
        ],
        PUBLIC,
    );
    fixture.history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![fixture.parent.identity()];
    let claims = [RequestRoot {
        path: b"/docs",
        domain: PUBLIC,
    }];
    let insufficient = signed(commit.clone(), &claims, "refs/heads/main:/docs", vec![]);
    fixture.history.insert_commit(insufficient.clone()).unwrap();
    assert!(
        verify_fixture_scope(&mut fixture.history, insufficient.identity(), defaults()).is_err()
    );

    let child_admin = signed_grants(
        commit.clone(),
        &claims,
        vec![Grant::new("refs/heads/main:/docs".to_string(), Verbs::new(16).unwrap()).unwrap()],
        vec![],
    );
    fixture.history.insert_commit(child_admin.clone()).unwrap();
    assert!(
        verify_fixture_scope(&mut fixture.history, child_admin.identity(), defaults()).is_err()
    );

    // An exact ancestor Admin grant need not match the child's Commit request.
    // It is evaluated against that independently witnessed prior ancestor.
    let original_admin = signed_grants(
        commit,
        &claims,
        vec![
            Grant::new("refs/heads/main:/docs".to_string(), Verbs::new(4).unwrap()).unwrap(),
            Grant::new("refs/heads/main:/".to_string(), Verbs::new(16).unwrap()).unwrap(),
        ],
        vec![],
    );
    fixture
        .history
        .insert_commit(original_admin.clone())
        .unwrap();
    let scope =
        verify_fixture_scope(&mut fixture.history, original_admin.identity(), defaults()).unwrap();
    assert_eq!(scope.changes().required_admin().len(), 2);
    assert_eq!(
        scope.changes().required_admin()[0].side(),
        RootSide::Previous
    );
    assert!(
        scope
            .changes()
            .required_admin()
            .iter()
            .any(|root| root.path() == b"/docs")
    );
}

#[test]
fn prov_commit_root_context_new_delegation_requires_original_ancestor_admin() {
    let mut fixture = fixture();
    let mut public = Vec::new();
    crate::cbor::write_text(&mut public, PUBLIC);
    let (delegated, bytes) = tree(
        vec![item(b"file", entry(b"new"))],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x6cbuild/public\x04",
            },
            Property {
                name: "domain",
                value: &public,
            },
        ]),
    );
    fixture
        .history
        .insert_tree(delegated, &[(delegated, bytes)])
        .unwrap();
    let (root, bytes) = domain_tree(
        vec![
            item(b"delegated", graft(delegated)),
            item(b"docs", graft(fixture.docs)),
            item(b"secret", graft(fixture.secret)),
        ],
        PUBLIC,
    );
    fixture.history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![fixture.parent.identity()];
    let claims = [RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }];
    let child_only = signed_grants(
        commit.clone(),
        &claims,
        vec![
            Grant::new("refs/heads/main".to_string(), Verbs::new(4).unwrap()).unwrap(),
            Grant::new(
                "refs/heads/main:/delegated".to_string(),
                Verbs::new(16).unwrap(),
            )
            .unwrap(),
        ],
        vec![],
    );
    fixture.history.insert_commit(child_only.clone()).unwrap();
    assert!(verify_fixture_scope(&mut fixture.history, child_only.identity(), defaults()).is_err());

    let ancestor = signed_grants(
        commit,
        &claims,
        vec![
            Grant::new("refs/heads/main".to_string(), Verbs::new(4).unwrap()).unwrap(),
            Grant::new("refs/heads/main:/".to_string(), Verbs::new(16).unwrap()).unwrap(),
        ],
        vec![],
    );
    fixture.history.insert_commit(ancestor.clone()).unwrap();
    let scope =
        verify_fixture_scope(&mut fixture.history, ancestor.identity(), defaults()).unwrap();
    assert_eq!(scope.changes().required_admin()[0].path(), b"/");
    assert_eq!(
        scope.changes().required_admin()[0].side(),
        RootSide::Previous
    );
}

#[test]
fn prov_commit_root_context_ancestor_admin_cannot_be_removed_by_child_policy() {
    for child_mask in [4, 16] {
        let mut public = Vec::new();
        crate::cbor::write_text(&mut public, PUBLIC);
        let mut child_acl = b"\x81\x82\x6cbuild/public".to_vec();
        crate::cbor::write_uint(&mut child_acl, child_mask);
        let (child, child_bytes) = tree(
            vec![item(b"file", entry(b"new"))],
            Some(vec![
                Property {
                    name: "acl",
                    value: &child_acl,
                },
                Property {
                    name: "domain",
                    value: &public,
                },
            ]),
        );
        let (root, root_bytes) = tree(
            vec![item(b"docs", graft(child))],
            Some(vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x6cbuild/public\x18\x1f",
                },
                Property {
                    name: "domain",
                    value: &public,
                },
            ]),
        );
        let mut commit = unsigned_commit();
        commit.tree = root;
        let signed = signed_grants(
            commit,
            &[RequestRoot {
                path: b"/",
                domain: PUBLIC,
            }],
            vec![Grant::new("refs/heads/main".to_string(), Verbs::new(16).unwrap()).unwrap()],
            vec![],
        );
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history.insert_tree(child, &[(child, child_bytes)]).unwrap();
        history.insert_tree(root, &[(root, root_bytes)]).unwrap();
        history.insert_commit(signed.clone()).unwrap();
        assert_eq!(
            verify_fixture_scope(&mut history, signed.identity(), defaults()).is_ok(),
            child_mask == 16
        );
    }
}

#[test]
fn prov_commit_root_context_public_child_cannot_widen_private_ancestor_domain() {
    let (child, child_bytes) = domain_tree(vec![item(b"file", entry(b"new"))], PUBLIC);
    let (root, root_bytes) = domain_tree(vec![item(b"docs", graft(child))], "private:ancestor");
    let mut commit = unsigned_commit();
    commit.tree = root;
    let signed = signed_grants(
        commit,
        &[
            RequestRoot {
                path: b"/",
                domain: "private:ancestor",
            },
            RequestRoot {
                path: b"/docs",
                domain: PUBLIC,
            },
        ],
        vec![Grant::new("refs/heads/main".to_string(), Verbs::new(16).unwrap()).unwrap()],
        vec![],
    );
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(child, &[(child, child_bytes)]).unwrap();
    history.insert_tree(root, &[(root, root_bytes)]).unwrap();
    history.insert_commit(signed.clone()).unwrap();
    assert!(verify_fixture_scope(&mut history, signed.identity(), defaults()).is_err());
}

#[test]
fn prov_commit_root_context_store_change_keeps_commit_scope_without_extra_admin() {
    let mut fixture = fixture();
    let (docs, bytes) = tree(
        vec![item(b"file", entry(b"old"))],
        Some(vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "store",
                value: b"\x65other",
            },
        ]),
    );
    fixture.history.insert_tree(docs, &[(docs, bytes)]).unwrap();
    let (root, bytes) = domain_tree(
        vec![
            item(b"docs", graft(docs)),
            item(b"secret", graft(fixture.secret)),
        ],
        PUBLIC,
    );
    fixture.history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = vec![fixture.parent.identity()];
    let signed = signed(
        commit,
        &[RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        }],
        "refs/heads/main:/docs",
        vec![],
    );
    fixture.history.insert_commit(signed.clone()).unwrap();
    let scope = verify_root_context(&mut fixture.history, signed.identity(), defaults()).unwrap();
    assert!(scope.changes().required_admin().is_empty());
    assert!(
        scope
            .changes()
            .affected()
            .iter()
            .all(|root| root.path() == b"/docs")
    );
}
