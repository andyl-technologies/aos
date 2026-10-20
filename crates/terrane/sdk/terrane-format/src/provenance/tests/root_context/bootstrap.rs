//! Exercises exact retained bootstrap inputs without candidate or current-policy inference.

use super::*;

fn initial(acl: &[(&str, u8)], token_mask: u8) -> (VerifiedHistory, VerifiedCommit) {
    let mut public = Vec::new();
    crate::cbor::write_text(&mut public, PUBLIC);
    let mut encoded = Vec::new();
    crate::cbor::write_array(&mut encoded, acl.len());
    for (name, verbs) in acl {
        crate::cbor::write_array(&mut encoded, 2);
        crate::cbor::write_text(&mut encoded, name);
        crate::cbor::write_uint(&mut encoded, u64::from(*verbs));
    }
    let (root, bytes) = tree(
        vec![item(b"file", entry(b"new"))],
        Some(vec![
            Property {
                name: "acl",
                value: &encoded,
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
        vec![
            Grant::new(
                "refs/heads/main".to_string(),
                Verbs::new(token_mask).unwrap(),
            )
            .unwrap(),
        ],
        vec![],
    );
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(signed.clone()).unwrap();
    (history, signed)
}

#[test]
fn prov_commit_bootstrap_initial_empty_acl_never_supplies_its_own_baseline() {
    let (mut history, signed) = initial(&[], 4);
    assert!(verify_root_context(&mut history, signed.identity(), defaults()).is_err());
    assert!(history.require_verified_context(signed.identity()).is_err());
    verify_fixture_scope(&mut history, signed.identity(), defaults()).unwrap();
    assert!(history.require_verified_context(signed.identity()).is_ok());
}

#[test]
fn prov_commit_bootstrap_matches_exact_original_authority_ref_epoch_and_schema() {
    let (history, signed) = initial(&[], 4);
    for policy in [
        OriginalBootstrapPolicy {
            authority: "wrong-physical-authority",
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            reference: "refs/heads/current",
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            writer_epoch: 5,
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            acl: &[("", 4)],
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            acl: &[("operator", 32)],
            ..fixture_bootstrap()
        },
    ] {
        let mut history = history.clone();
        assert!(
            verify_root_context_with_bootstrap(
                &mut history,
                signed.identity(),
                defaults(),
                fixture_bootstrap().authority,
                policy
            )
            .is_err()
        );
        assert!(history.require_verified_context(signed.identity()).is_err());
    }
    let mut history = history;
    assert!(
        verify_root_context_with_bootstrap(
            &mut history,
            signed.identity(),
            defaults(),
            "",
            fixture_bootstrap()
        )
        .is_err()
    );
}

#[test]
fn prov_commit_bootstrap_retaining_and_narrowing_admin_implications_need_only_commit() {
    for baseline in [4, 16, 31] {
        let (mut history, signed) = initial(&[("operator", 4)], 4);
        let acl = [("operator", baseline)];
        let before = signed.commit().encode().unwrap();
        let scope = verify_root_context_with_bootstrap(
            &mut history,
            signed.identity(),
            defaults(),
            fixture_bootstrap().authority,
            OriginalBootstrapPolicy {
                acl: &acl,
                ..fixture_bootstrap()
            },
        )
        .unwrap();
        assert!(scope.changes().required_admin().is_empty());
        assert_eq!(signed.commit().encode().unwrap(), before);
    }
}

#[test]
fn prov_commit_bootstrap_widening_needs_original_view_root_admin() {
    for token_mask in [4, 16] {
        let (mut history, signed) = initial(&[("operator", 16)], token_mask);
        let scope = verify_root_context_with_bootstrap(
            &mut history,
            signed.identity(),
            defaults(),
            fixture_bootstrap().authority,
            OriginalBootstrapPolicy {
                acl: &[("operator", 4)],
                ..fixture_bootstrap()
            },
        );
        assert_eq!(scope.is_ok(), token_mask == 16);
        if let Ok(scope) = scope {
            assert_eq!(scope.changes().required_admin().len(), 1);
            assert_eq!(scope.changes().required_admin()[0].path(), b"/");
            assert_eq!(
                scope.changes().required_admin()[0].side(),
                RootSide::Candidate
            );
        } else {
            assert!(history.require_verified_context(signed.identity()).is_err());
        }
    }
}

#[test]
fn prov_commit_bootstrap_conflicting_retained_association_cannot_replace_evidence() {
    let (mut history, signed) = initial(&[], 4);
    verify_fixture_scope(&mut history, signed.identity(), defaults()).unwrap();
    let conflicting = OriginalBootstrapPolicy {
        acl: &[("operator", 4)],
        ..fixture_bootstrap()
    };
    assert!(
        verify_root_context_with_bootstrap(
            &mut history,
            signed.identity(),
            defaults(),
            fixture_bootstrap().authority,
            conflicting
        )
        .is_err()
    );
    assert!(history.require_verified_context(signed.identity()).is_ok());

    let (mut other, _) = initial(&[], 4);
    verify_root_context_with_bootstrap(
        &mut other,
        signed.identity(),
        defaults(),
        fixture_bootstrap().authority,
        conflicting,
    )
    .unwrap();
    assert!(history.append_evidence(&other).is_err());
    assert!(history.require_verified_context(signed.identity()).is_ok());
}

#[test]
fn prov_commit_bootstrap_descendant_compares_actual_parent_not_namespace_baseline() {
    for token_mask in [4, 16] {
        let mut public = Vec::new();
        crate::cbor::write_text(&mut public, PUBLIC);
        let (child, child_bytes) = tree(
            vec![item(b"file", entry(b"new"))],
            Some(vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x65extra\x04",
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
                    value: b"\x81\x82\x68operator\x04",
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
            vec![
                Grant::new(
                    "refs/heads/main".to_string(),
                    Verbs::new(token_mask).unwrap(),
                )
                .unwrap(),
            ],
            vec![],
        );
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history.insert_tree(child, &[(child, child_bytes)]).unwrap();
        history.insert_tree(root, &[(root, root_bytes)]).unwrap();
        history.insert_commit(signed.clone()).unwrap();
        let baseline = OriginalBootstrapPolicy {
            acl: &[("operator", 4), ("extra", 4)],
            ..fixture_bootstrap()
        };
        let scope = verify_root_context_with_bootstrap(
            &mut history,
            signed.identity(),
            defaults(),
            fixture_bootstrap().authority,
            baseline,
        );
        assert_eq!(scope.is_ok(), token_mask == 16);
    }
}

#[test]
fn prov_commit_bootstrap_protected_acl_is_not_public_history_debug_metadata() {
    let (mut history, signed) = initial(&[], 4);
    let policy = OriginalBootstrapPolicy {
        acl: &[("private-bootstrap-control-principal", 16)],
        ..fixture_bootstrap()
    };
    verify_root_context_with_bootstrap(
        &mut history,
        signed.identity(),
        defaults(),
        fixture_bootstrap().authority,
        policy,
    )
    .unwrap();
    let debug = alloc::format!("{history:?}");
    assert!(!debug.contains("private-bootstrap-control-principal"));
}

fn ordinary() -> (VerifiedHistory, VerifiedCommit) {
    let (mut history, parent) = initial(&[], 4);
    verify_fixture_scope(&mut history, parent.identity(), defaults()).unwrap();
    let mut commit = parent.commit().clone();
    commit.parents = vec![parent.identity()];
    commit.message = "ordinary unchanged view".to_string();
    let signed = signed(
        commit,
        &[RequestRoot {
            path: b"/",
            domain: PUBLIC,
        }],
        "refs/heads/main",
        vec![],
    );
    history.insert_commit(signed.clone()).unwrap();
    (history, signed)
}

#[test]
fn prov_commit_bootstrap_ordinary_append_preserves_compatible_annotations_in_both_orders() {
    let (history, signed) = ordinary();
    let mut unannotated = history.clone();
    verify_root_context(&mut unannotated, signed.identity(), defaults()).unwrap();
    let mut annotated = history;
    let expected = verify_fixture_scope(&mut annotated, signed.identity(), defaults()).unwrap();

    for (mut destination, source) in [
        (unannotated.clone(), annotated.clone()),
        (annotated, unannotated),
    ] {
        destination.append_evidence(&source).unwrap();
        assert_eq!(destination.root_scopes[&signed.identity()], expected);
        assert!(
            destination
                .require_verified_context(signed.identity())
                .is_ok()
        );
    }
}

#[test]
fn prov_commit_bootstrap_ordinary_reverification_never_drops_retained_evidence() {
    let (history, signed) = ordinary();
    for annotate_first in [false, true] {
        let mut history = history.clone();
        if !annotate_first {
            verify_root_context(&mut history, signed.identity(), defaults()).unwrap();
        }
        let annotated = verify_fixture_scope(&mut history, signed.identity(), defaults()).unwrap();
        let repeated = verify_root_context(&mut history, signed.identity(), defaults()).unwrap();
        assert_eq!(annotated, repeated);
        assert_eq!(history.root_scopes[&signed.identity()], annotated);
    }
}

#[test]
fn prov_commit_bootstrap_ordinary_conflicting_annotation_is_atomic() {
    let (mut history, signed) = ordinary();
    let original = verify_fixture_scope(&mut history, signed.identity(), defaults()).unwrap();
    for policy in [
        OriginalBootstrapPolicy {
            authority: "other-physical-authority",
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            acl: &[("operator", 4)],
            ..fixture_bootstrap()
        },
    ] {
        let before = history.bootstrap_policies.clone();
        assert!(
            verify_root_context_with_bootstrap(
                &mut history,
                signed.identity(),
                defaults(),
                policy.authority,
                policy,
            )
            .is_err()
        );
        assert_eq!(history.root_scopes[&signed.identity()], original);
        assert_eq!(history.bootstrap_policies, before);
    }
}
