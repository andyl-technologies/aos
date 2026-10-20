//! Exercises recorded interpretation with actual authenticated root-scope verification.
//!
//! Literal property/name inputs are independently justified fixture configuration.
//! No test constructs a checked scope or sets history completion/provisional flags.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::algebra::{MergePolicy, Recipe};
use crate::properties::semantics::{RecordedContext, associations::RecordedAssociation};
use alloc::string::String;

#[path = "recorded/fixtures.rs"]
mod fixtures;
use fixtures::*;

fn root_claim() -> RequestRoot<'static> {
    RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }
}

fn check_unchanged(history: &VerifiedHistory, before: &VerifiedHistory) {
    assert_eq!(history.root_scopes, before.root_scopes);
    assert_eq!(history.bootstrap_policies, before.bootstrap_policies);
    assert_eq!(history.commits, before.commits);
}

fn legacy_scope(
    history: &mut VerifiedHistory,
    view: Digest,
    defaults: Defaults<'_>,
) -> Result<VerifiedRootScope, Rejected> {
    if history.property_selection(view)? != crate::properties::selected::Selection::Legacy {
        return Err(Rejected);
    }
    verify_fixture_scope(history, view, defaults)
}

fn selected_evaluator(
    history: &VerifiedHistory,
    record: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) -> Result<TrustContext, Rejected> {
    TrustContext::new_with_recorded(
        history,
        record.identity(),
        Selector::preset(Preset::Any),
        PUBLIC,
        None,
        Some((
            record.identity(),
            record.commit().tree,
            RecordedContext::new(revision, 3, later).unwrap(),
        )),
    )
}

#[test]
fn recorded_scope_verification_preserves_fixed_interpretations_and_original_authority() {
    for revision in 1..=3 {
        let mut history = VerifiedHistory::new(MINIMUM);
        let child = store_tree(
            &mut history,
            vec![item(b"file", entry(b"old"))],
            properties(revision),
        );
        let mut mounted = graft(child);
        if let EntryKind::Tree { props, .. } = &mut mounted.kind {
            let mut overrides = properties(revision);
            overrides.retain(|property| property.name != "domain");
            overrides.push(Property {
                name: "retain",
                value: b"\x67forever",
            });
            *props = Some(overrides);
        }
        let root = store_tree(
            &mut history,
            vec![
                item(b"docs", mounted.clone()),
                item(b"shared", graft(child)),
            ],
            properties(revision),
        );
        let parent = retained(
            &mut history,
            root,
            vec![],
            "parent",
            &[root_claim()],
            grants(false),
            vec![],
            &RecordedContext::new(revision, 3, later(revision)).unwrap(),
        );
        let selected = association(&parent, revision, later(revision));
        let before = history.clone();
        if revision < 3 {
            let mut current = history
                .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                    parent.identity(),
                    crate::properties::selected::Selection::Active,
                )]))
                .unwrap();
            let current_before = current.clone();
            assert!(verify_fixture_scope(&mut current, parent.identity(), defaults()).is_err());
            check_unchanged(&current, &current_before);
            check_unchanged(&history, &before);
        }
        let fresh = check(&mut history, &parent, &selected).unwrap();
        assert!(fresh.changes().fresh());
        assert_eq!(fresh.claims().len(), 1);
        let units: Vec<_> = fresh
            .changes()
            .affected()
            .iter()
            .map(|unit| (unit.path().to_vec(), unit.root(), unit.side()))
            .collect();
        assert_eq!(
            units,
            vec![
                (b"/".to_vec(), root, RootSide::Candidate),
                (b"/docs".to_vec(), child, RootSide::Candidate),
                (b"/shared".to_vec(), child, RootSide::Candidate)
            ]
        );
        assert!(fresh.matches_properties(Some(&selected)));

        // The moved occurrence witnesses a removed claim through the actual first parent.
        let moved = store_tree(
            &mut history,
            vec![item(b"moved", mounted), item(b"shared", graft(child))],
            properties(revision),
        );
        let claims = [
            root_claim(),
            RequestRoot {
                path: b"/docs",
                domain: PUBLIC,
            },
            RequestRoot {
                path: b"/moved",
                domain: PUBLIC,
            },
        ];
        let candidate = retained(
            &mut history,
            moved,
            vec![parent.identity()],
            "move",
            &claims,
            grants(false),
            vec![],
            &RecordedContext::new(revision, 3, later(revision)).unwrap(),
        );
        let candidate_input = association(&candidate, revision, later(revision));
        let scope = check(&mut history, &candidate, &candidate_input).unwrap();
        assert!(!scope.changes().fresh());
        assert_eq!(scope.changes().first_parent(), Some(parent.identity()));
        assert!(
            scope
                .claims()
                .iter()
                .any(|claim| claim.path() == b"/docs" && claim.side() == RootSide::Previous)
        );
        assert!(
            scope
                .claims()
                .iter()
                .any(|claim| claim.path() == b"/moved" && claim.side() == RootSide::Candidate)
        );
        assert!(
            !scope
                .changes()
                .affected()
                .iter()
                .any(|unit| unit.path() == b"/shared")
        );
        assert!(
            scope
                .changes()
                .affected()
                .iter()
                .any(|unit| unit.path() == b"/docs" && unit.root() == child)
        );
        assert!(
            scope
                .changes()
                .affected()
                .iter()
                .any(|unit| unit.path() == b"/moved" && unit.root() == child)
        );

        // Equal physical bytes keep the bounded empty-plan shortcut, not fresh authority.
        let copied = retained(
            &mut history,
            moved,
            vec![candidate.identity()],
            "copy",
            &[root_claim()],
            grants(false),
            vec![],
            &RecordedContext::new(revision, 3, later(revision)).unwrap(),
        );
        let copied_input = association(&copied, revision, later(revision));
        let copied_scope = check(&mut history, &copied, &copied_input).unwrap();
        assert!(!copied_scope.changes().fresh());
        assert!(copied_scope.changes().affected().is_empty());
        assert_eq!(copied_scope.claims().len(), 1);
        assert_eq!(copied_scope.claims()[0].root(), moved);

        let untouched = history.clone();
        for invalid in [
            None,
            Some(RecordedAssociation::new(
                [9; 32],
                moved,
                RecordedContext::new(revision, 3, later(revision)).unwrap(),
            )),
            Some(RecordedAssociation::new(
                copied.identity(),
                [9; 32],
                RecordedContext::new(revision, 3, later(revision)).unwrap(),
            )),
        ] {
            assert!(
                VerifiedRootScope::verify_with_recorded_properties_and_bootstrap(
                    &mut history,
                    copied.identity(),
                    defaults(),
                    invalid.as_ref(),
                    fixture_bootstrap().authority,
                    fixture_bootstrap(),
                )
                .is_err()
            );
            check_unchanged(&history, &untouched);
        }
    }

    original_authority_refusals_and_admin_paths();
    selected_placement_and_bounded_copy_controls();
}

fn selected_placement_and_bounded_copy_controls() {
    let mut owner_binding = head(5, 2);
    for field in [
        text("value"),
        head(5, 1),
        text("uid"),
        text(&"0".repeat(64)),
        text("inherit"),
        vec![0xf4],
    ] {
        owner_binding.extend(field);
    }
    let mut gap_binding = head(5, 2);
    for field in [
        text("value"),
        text(&"0".repeat(64)),
        text("inherit"),
        vec![0xf4],
    ] {
        gap_binding.extend(field);
    }
    for revision in [1, 2, 3] {
        let mut history = VerifiedHistory::new(MINIMUM);
        let child = store_tree(
            &mut history,
            vec![item(b"file", entry(b"child"))],
            vec![Property {
                name: "domain",
                value: b"\x66public",
            }],
        );
        let root = store_tree(
            &mut history,
            vec![item(b"docs", graft(child))],
            vec![
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "index-roots",
                    value: &owner_binding,
                },
            ],
        );
        let record = retained(
            &mut history,
            root,
            vec![],
            "owner metadata",
            &[root_claim()],
            grants(false),
            vec![],
            &RecordedContext::new(revision, 3, later(revision)).unwrap(),
        );
        let input = association(&record, revision, later(revision));
        let scope = check(&mut history, &record, &input).unwrap();
        assert_eq!(scope.changes().affected().len(), 2);
        assert_eq!(
            history.root_properties(root).unwrap()[1].value,
            owner_binding
        );
        assert!(
            history
                .root_properties(child)
                .unwrap()
                .iter()
                .all(|property| property.name != "index-roots")
        );

        let mut overridden = graft(child);
        if let EntryKind::Tree { props, .. } = &mut overridden.kind {
            *props = Some(vec![Property {
                name: "index-roots",
                value: &owner_binding,
            }]);
        }
        let invalid_root = store_tree(
            &mut history,
            vec![item(b"docs", overridden)],
            vec![Property {
                name: "domain",
                value: b"\x66public",
            }],
        );
        let invalid = retained(
            &mut history,
            invalid_root,
            vec![],
            "graft metadata",
            &[root_claim()],
            grants(false),
            vec![],
            &RecordedContext::new(revision, 3, later(revision)).unwrap(),
        );
        let before = history.clone();
        let result = check(
            &mut history,
            &invalid,
            &association(&invalid, revision, later(revision)),
        );
        if revision == 1 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
            check_unchanged(&history, &before);
        }

        let gap_root = store_tree(
            &mut history,
            vec![item(b"file", entry(b"gap"))],
            vec![
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "index-gaps",
                    value: &gap_binding,
                },
            ],
        );
        let gap = retained(
            &mut history,
            gap_root,
            vec![],
            "namespace gap",
            &[root_claim()],
            grants(false),
            vec![],
            &RecordedContext::new(revision, 3, later(revision)).unwrap(),
        );
        let before = history.clone();
        let result = check(
            &mut history,
            &gap,
            &association(&gap, revision, later(revision)),
        );
        if revision < 3 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
            check_unchanged(&history, &before);
        }
    }

    // Only the main canonical witness is retained. The legacy parent is genuinely
    // signed and reverified, but has no modern root-scope annotation to fabricate.
    let mut history = VerifiedHistory::new(MINIMUM);
    let absent_child = [0x73; 32];
    let root = store_tree(
        &mut history,
        vec![item(b"docs", graft(absent_child))],
        properties(1),
    );
    let mut original = unsigned_commit();
    original.tree = root;
    let signed =
        with_request(|request| sign(original, &[9; 32], &issuer_keys(), request, 4).unwrap());
    let parent =
        with_request(|request| verify(signed.commit(), &issuer_keys(), request, 4).unwrap());
    assert!(parent.commit().profile_pair.commit_context.is_none());
    history
        .insert_commit_selected(
            parent.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(1, 3, later(1)).unwrap(),
            ),
        )
        .unwrap();
    assert!(history.root_properties(absent_child).is_err());
    let copied = retained(
        &mut history,
        root,
        vec![parent.identity()],
        "bounded historical copy",
        &[root_claim()],
        grants(false),
        vec![],
        &RecordedContext::new(1, 3, later(1)).unwrap(),
    );
    let input = association(&copied, 1, later(1));
    let scope = check(&mut history, &copied, &input).unwrap();
    assert!(!scope.changes().fresh());
    assert!(scope.changes().affected().is_empty());
    assert_eq!(scope.claims().len(), 1);
    assert_eq!(scope.claims()[0].root(), root);
    assert!(history.root_properties(absent_child).is_err());
}

fn original_authority_refusals_and_admin_paths() {
    let (history, record) = modern();
    let input = association(&record, 1, &["index-roots", "index-gaps"]);
    let mut missing = history.clone();
    assert!(
        VerifiedRootScope::verify_with_recorded_properties(
            &mut missing,
            record.identity(),
            defaults(),
            Some(&input)
        )
        .is_err()
    );
    check_unchanged(&missing, &history);
    for policy in [
        OriginalBootstrapPolicy {
            authority: "wrong",
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            reference: "refs/heads/wrong",
            ..fixture_bootstrap()
        },
        OriginalBootstrapPolicy {
            writer_epoch: 5,
            ..fixture_bootstrap()
        },
    ] {
        let mut candidate = history.clone();
        assert!(
            VerifiedRootScope::verify_with_recorded_properties_and_bootstrap(
                &mut candidate,
                record.identity(),
                defaults(),
                Some(&input),
                fixture_bootstrap().authority,
                policy,
            )
            .is_err()
        );
        check_unchanged(&candidate, &history);
    }
    let mut absent_root = VerifiedHistory::new(MINIMUM);
    absent_root.insert_commit(record.clone()).unwrap();
    assert!(check(&mut absent_root, &record, &input).is_err());
    assert!(absent_root.root_scopes.is_empty());
    let mut absent_parent = history.clone();
    let unknown = retained(
        &mut absent_parent,
        record.commit().tree,
        vec![[9; 32]],
        "unknown first parent",
        &[root_claim()],
        grants(false),
        vec![],
        &RecordedContext::new(1, 3, later(1)).unwrap(),
    );
    let before = absent_parent.clone();
    assert!(
        check(
            &mut absent_parent,
            &unknown,
            &association(&unknown, 1, later(1))
        )
        .is_err()
    );
    check_unchanged(&absent_parent, &before);
    let mut mislabeled = history.clone();
    let wrong_domain = retained(
        &mut mislabeled,
        record.commit().tree,
        vec![],
        "wrong root domain",
        &[RequestRoot {
            path: b"/",
            domain: "other",
        }],
        grants(false),
        vec![],
        &RecordedContext::new(1, 3, later(1)).unwrap(),
    );
    let before = mislabeled.clone();
    assert!(
        check(
            &mut mislabeled,
            &wrong_domain,
            &association(&wrong_domain, 1, later(1))
        )
        .is_err()
    );
    check_unchanged(&mislabeled, &before);
    let mut damaged = record.commit().clone();
    damaged.message.push_str(" altered");
    assert!(
        verify_history(
            &damaged,
            &issuer_keys(),
            &[root_claim()],
            &[("refs/heads/main", 4)]
        )
        .is_err()
    );
    damaged = record.commit().clone();
    damaged.provenance.embedded_token = None;
    assert!(
        verify_history(
            &damaged,
            &issuer_keys(),
            &[root_claim()],
            &[("refs/heads/main", 4)]
        )
        .is_err()
    );
    damaged = record.commit().clone();
    damaged.signature = Some([0; 64]);
    assert!(
        verify_history(
            &damaged,
            &issuer_keys(),
            &[root_claim()],
            &[("refs/heads/main", 4)]
        )
        .is_err()
    );
    let epoch_record = signed_grants(
        unsigned_commit(),
        &[root_claim()],
        grants(false),
        vec![Caveat::Epoch("refs/heads/main".to_string(), 4)],
    );
    assert!(
        verify_history(
            epoch_record.commit(),
            &issuer_keys(),
            &[root_claim()],
            &[("refs/heads/main", 5)]
        )
        .is_err()
    );

    // Active candidate ACL widening requires original Admin, even with a valid signature.
    for admin in [false, true] {
        let mut history = VerifiedHistory::new(MINIMUM);
        let root = store_tree(
            &mut history,
            vec![item(b"file", entry(b"new"))],
            vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x6cbuild/public\x04",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "index-gaps",
                    value: &[0],
                },
                Property {
                    name: "index-roots",
                    value: &[0],
                },
            ],
        );
        let record = retained(
            &mut history,
            root,
            vec![],
            "initial ACL",
            &[root_claim()],
            grants(admin),
            vec![],
            &RecordedContext::new(1, 3, later(1)).unwrap(),
        );
        let input = association(&record, 1, later(1));
        let result = check(&mut history, &record, &input);
        if admin {
            assert!(!result.unwrap().changes().required_admin().is_empty());
        } else {
            assert!(result.is_err());
            assert!(history.root_scopes.is_empty());
            assert!(history.bootstrap_policies.is_empty());
        }
    }

    // Fresh child delegation checks the actual enclosing ancestor under legacy interpretation.
    for admin in [false, true] {
        let mut history = VerifiedHistory::new(MINIMUM);
        let child = store_tree(
            &mut history,
            vec![item(b"file", entry(b"new"))],
            vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x6cbuild/public\x04",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "index-gaps",
                    value: &[0],
                },
                Property {
                    name: "index-roots",
                    value: &[0],
                },
            ],
        );
        let root = store_tree(
            &mut history,
            vec![item(b"docs", graft(child))],
            properties(1),
        );
        let record = retained(
            &mut history,
            root,
            vec![],
            "fresh delegation",
            &[root_claim()],
            grants(admin),
            vec![],
            &RecordedContext::new(1, 3, later(1)).unwrap(),
        );
        let before = history.clone();
        let result = check(&mut history, &record, &association(&record, 1, later(1)));
        if admin {
            assert!(
                result
                    .unwrap()
                    .changes()
                    .required_admin()
                    .iter()
                    .any(|unit| unit.path() == b"/" && unit.side() == RootSide::Candidate)
            );
        } else {
            assert!(result.is_err());
            check_unchanged(&history, &before);
        }
    }

    // Prior-ancestor Admin checks traverse inert legacy prefixes.
    for admin in [false, true] {
        let mut history = VerifiedHistory::new(MINIMUM);
        let child = store_tree(
            &mut history,
            vec![item(b"file", entry(b"old"))],
            properties(1),
        );
        let root = store_tree(
            &mut history,
            vec![item(b"docs", graft(child))],
            properties(1),
        );
        let parent = retained(
            &mut history,
            root,
            vec![],
            "original",
            &[root_claim()],
            grants(false),
            vec![],
            &RecordedContext::new(1, 3, later(1)).unwrap(),
        );
        check(&mut history, &parent, &association(&parent, 1, later(1))).unwrap();
        let changed_child = store_tree(
            &mut history,
            vec![item(b"file", entry(b"old"))],
            vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x6cbuild/public\x04",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "index-gaps",
                    value: &[0],
                },
                Property {
                    name: "index-roots",
                    value: &[0],
                },
            ],
        );
        let changed = store_tree(
            &mut history,
            vec![item(b"docs", graft(changed_child))],
            properties(1),
        );
        let claims = [RequestRoot {
            path: b"/docs",
            domain: PUBLIC,
        }];
        let mut tokens =
            vec![Grant::new("refs/heads/main:/docs".to_string(), Verbs::new(4).unwrap()).unwrap()];
        if admin {
            tokens.push(
                Grant::new("refs/heads/main:/".to_string(), Verbs::new(16).unwrap()).unwrap(),
            );
        }
        let candidate = retained(
            &mut history,
            changed,
            vec![parent.identity()],
            "child ACL",
            &claims,
            tokens,
            vec![],
            &RecordedContext::new(1, 3, later(1)).unwrap(),
        );
        let input = association(&candidate, 1, later(1));
        let before = history.clone();
        let checked = check(&mut history, &candidate, &input);
        if admin {
            let scope = checked.unwrap();
            assert!(
                scope
                    .changes()
                    .required_admin()
                    .iter()
                    .any(|root| root.path() == b"/docs" && root.side() == RootSide::Previous)
            );
        } else {
            assert!(checked.is_err());
            check_unchanged(&history, &before);
        }
    }
}

#[test]
fn recorded_scope_reverification_and_history_union_refuse_interpretation_conflicts() {
    let (base, record) = modern();
    let selections = [
        None,
        Some((1, vec!["future.a", "future.b"])),
        Some((2, vec!["future.a", "future.b"])),
        Some((3, vec![])),
        Some((3, vec!["future.a"])),
    ];
    let histories: Vec<_> = selections
        .iter()
        .map(|mode| {
            let selected = match mode {
                None => crate::properties::selected::Selection::Legacy,
                Some((revision, names)) => crate::properties::selected::Selection::Recorded(
                    RecordedContext::new(*revision, 3, names).unwrap(),
                ),
            };
            let mut history = base
                .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                    record.identity(),
                    selected,
                )]))
                .unwrap();
            match mode {
                None => {
                    legacy_scope(&mut history, record.identity(), defaults()).unwrap();
                }
                Some((revision, names)) => {
                    check(
                        &mut history,
                        &record,
                        &association(&record, *revision, names),
                    )
                    .unwrap();
                }
            }
            history
        })
        .collect();
    for (left, source) in histories.iter().enumerate() {
        for (right, other) in histories.iter().enumerate() {
            let mut union = source.clone();
            let before = union.clone();
            if left == right {
                union.append_verified(other).unwrap();
                check_unchanged(&union, &before);
            } else {
                assert!(
                    union.append_verified(other).is_err(),
                    "union {left} <- {right}"
                );
                check_unchanged(&union, &before);
                let result = match &selections[right] {
                    None => legacy_scope(&mut union, record.identity(), defaults()),
                    Some((revision, names)) => {
                        check(&mut union, &record, &association(&record, *revision, names))
                    }
                };
                assert!(result.is_err(), "reverify {left} <- {right}");
                check_unchanged(&union, &before);
            }
        }
    }
    let mut retained_history = histories[1].clone();
    let input = {
        let owned = [String::from("future.b"), String::from("future.a")];
        let borrowed = owned.iter().map(String::as_str).collect::<Vec<_>>();
        association(&record, 1, &borrowed)
    };
    let prior = retained_history
        .root_scopes
        .get(&record.identity())
        .unwrap()
        .clone();
    let repeated = check(&mut retained_history, &record, &input).unwrap();
    assert_eq!(prior, repeated);
    assert!(repeated.matches_properties(Some(&input)));
    assert_eq!(input.later_registered(), ["future.a", "future.b"]);

    // Distinct views sharing a physical root can retain independently different revisions.
    let other = retained(
        &mut retained_history,
        record.commit().tree,
        vec![record.identity()],
        "different view",
        &[root_claim()],
        grants(false),
        vec![],
        &RecordedContext::new(3, 3, later(3)).unwrap(),
    );
    let different = association(&other, 3, &[]);
    let scope = VerifiedRootScope::verify_with_recorded_properties(
        &mut retained_history,
        other.identity(),
        defaults(),
        Some(&different),
    )
    .unwrap();
    let enriched = check(&mut retained_history, &other, &different).unwrap();
    assert_ne!(scope, enriched);
    let repeated = VerifiedRootScope::verify_with_recorded_properties(
        &mut retained_history,
        other.identity(),
        defaults(),
        Some(&different),
    )
    .unwrap();
    assert_eq!(repeated, enriched);
    assert!(scope.matches_properties(Some(&different)));
    assert!(
        retained_history
            .root_scopes
            .get(&record.identity())
            .unwrap()
            .matches_properties(Some(&input))
    );
}

#[test]
fn recorded_scope_evaluators_require_matching_retained_interpretations() {
    let (base, record) = modern();
    let mut contexts = Vec::new();
    let mut evaluators = Vec::new();
    for revision in 1..=3 {
        let names = later(revision);
        let input = association(&record, revision, names);
        let mut history = base
            .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                record.identity(),
                crate::properties::selected::Selection::Recorded(input.context().clone()),
            )]))
            .unwrap();
        check(&mut history, &record, &input).unwrap();
        let evaluator = selected_evaluator(&history, &record, revision, names).unwrap();
        let expected = context(&record, revision, names);
        assert_eq!(evaluator.canonical_context(), expected);
        assert!(evaluator.accepts_path(b"file"));
        assert!(
            TrustContext::new_with_recorded(
                &history,
                record.identity(),
                Selector::preset(Preset::Any),
                PUBLIC,
                None,
                None,
            )
            .is_err()
        );
        assert!(selected_evaluator(&history, &record, revision, &["future.changed"]).is_err());
        let other_revision = if revision == 1 { 3 } else { 1 };
        assert!(selected_evaluator(&history, &record, other_revision, &[]).is_err());
        contexts.push(expected);
        evaluators.push(evaluator);
    }
    let mut current = base
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            record.identity(),
            crate::properties::selected::Selection::Legacy,
        )]))
        .unwrap();
    legacy_scope(&mut current, record.identity(), defaults()).unwrap();
    assert!(selected_evaluator(&current, &record, 3, &[]).is_err());
    let legacy = TrustContext::new(
        &current,
        record.identity(),
        Selector::preset(Preset::Any),
        PUBLIC,
        None,
    )
    .unwrap();
    let expected_legacy = array(&[
        head(0, 1),
        bytes(&record.identity()),
        text(PUBLIC),
        bytes(&array(&[text("preset"), text("any")])),
        vec![0xf6],
        head(0, MINIMUM),
    ]);
    assert_eq!(legacy.canonical_context(), expected_legacy);
    assert!(legacy.accepts_path(b"file"));
    assert_ne!(expected_legacy, contexts[2]);

    // Configuration binds complete independent contexts without granting recipe authority.
    let mut other_history = base.clone();
    let other = retained(
        &mut other_history,
        record.commit().tree,
        vec![],
        "other evaluator view",
        &[root_claim()],
        grants(false),
        vec![receipt(
            record.commit().tree,
            crate::refs::EntryOrigin::Current,
        )],
        &RecordedContext::new(3, 3, later(3)).unwrap(),
    );
    check(&mut other_history, &other, &association(&other, 3, &[])).unwrap();
    let other_evaluator = selected_evaluator(&other_history, &other, 3, &[]).unwrap();
    let other_context = context(&other, 3, &[]);
    assert_eq!(other_evaluator.canonical_context(), other_context);
    let policy = crate::algebra::TrustContext::from_verified(vec![
        evaluators[0].clone(),
        other_evaluator.clone(),
    ])
    .unwrap();
    let expected_configuration = array(&[
        array(&[bytes(&contexts[0]), bytes(&other_context)]),
        vec![0xf6],
    ]);
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let root = record.commit().tree;
    let recipe = Recipe::Merge {
        base: root,
        ours: root,
        theirs: root,
        policies: &policies,
        trust: &policy,
        domains: None,
    };
    let wire = recipe.encode();
    let decoded = Recipe::decode(&wire).unwrap();
    assert_eq!(decoded.as_recipe().encode(), wire);
    assert_eq!(
        decoded.as_recipe().identity().unwrap(),
        recipe.identity().unwrap()
    );
    let rebound = Recipe::decode(&wire)
        .unwrap()
        .bind_verified(vec![evaluators[0].clone(), other_evaluator.clone()])
        .unwrap();
    assert_eq!(rebound.as_recipe().encode(), wire);
    assert!(
        Recipe::decode(&wire)
            .unwrap()
            .bind_verified(vec![other_evaluator, evaluators[0].clone()])
            .is_err()
    );
    let mut expected_trust = head(5, 4);
    for field in [
        head(0, 1),
        array(&[text("preset"), text("any")]),
        head(0, 2),
        text("terrane-verified-path/v1"),
        head(0, 3),
        expected_configuration,
        head(0, 4),
        array(&[]),
    ] {
        expected_trust.extend(field);
    }
    let mut expected_wire = head(5, 3);
    for field in [
        head(0, 1),
        text("merge"),
        head(0, 2),
        array(&[bytes(&root), bytes(&root), bytes(&root)]),
        head(0, 3),
        head(5, 2),
        text("trust"),
        expected_trust,
        text("policy"),
        array(&[text("prefer-trusted"), text("keep-conflict")]),
    ] {
        expected_wire.extend(field);
    }
    assert_eq!(wire, expected_wire);
    let mut memo_preimage = b"terrane-memo-v1\0".to_vec();
    memo_preimage.extend_from_slice(&expected_wire);
    assert_eq!(
        recipe.identity().unwrap(),
        *blake3::hash(&memo_preimage).as_bytes()
    );
}
