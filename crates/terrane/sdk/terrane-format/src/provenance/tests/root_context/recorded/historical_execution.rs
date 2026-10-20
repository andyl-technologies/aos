//! Checks candidate interpretation of raw prior scope independently of parent verification.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use alloc::borrow::ToOwned;

#[test]
fn recorded_removed_scope_uses_candidate_interpretation_of_raw_prior_roots() {
    let (child, child_wire) = tree(
        vec![],
        Some(vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-gaps",
                value: b"\x81\x00",
            },
        ]),
    );
    let (prior_root, prior_wire) = domain_tree(vec![item(b"removed", graft(child))], PUBLIC);
    let (candidate_root, candidate_wire) = domain_tree(vec![], PUBLIC);
    let claims = [
        RequestRoot {
            path: b"/",
            domain: PUBLIC,
        },
        RequestRoot {
            path: b"/removed",
            domain: PUBLIC,
        },
    ];
    let mut prior_record = unsigned_commit();
    prior_record.tree = prior_root;
    let prior = signed(prior_record, &claims, "refs/heads/main", vec![]);
    let mut candidate_record = unsigned_commit();
    candidate_record.tree = candidate_root;
    candidate_record.parents = vec![prior.identity()];
    candidate_record.message = "removed actual child".into();
    let candidate = signed(candidate_record, &claims, "refs/heads/main", vec![]);

    for later in [&["index-gaps"][..], &[][..]] {
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        for (root, wire) in [
            (child, &child_wire),
            (prior_root, &prior_wire),
            (candidate_root, &candidate_wire),
        ] {
            history.insert_tree(root, &[(root, wire.clone())]).unwrap();
        }
        let parent_selection =
            Selection::Recorded(RecordedContext::new(2, 3, &["index-gaps"]).unwrap());
        history
            .insert_commit_selected(prior.clone(), parent_selection.clone())
            .unwrap();
        let parent_scope =
            verify_fixture_scope(&mut history, prior.identity(), defaults()).unwrap();
        assert_eq!(parent_scope.view(), prior.identity());
        let candidate_selection = Selection::Recorded(RecordedContext::new(1, 3, later).unwrap());
        history
            .insert_commit_selected(candidate.clone(), candidate_selection.clone())
            .unwrap();
        let checked = verify_fixture_scope(&mut history, candidate.identity(), defaults());
        if later.is_empty() {
            assert!(checked.is_err());
            assert!(
                history
                    .require_verified_context(candidate.identity())
                    .is_err()
            );
        } else {
            let scope = checked.unwrap();
            assert!(!scope.changes().fresh());
            assert_eq!(scope.changes().first_parent(), Some(prior.identity()));
            assert_eq!(scope.changes().candidate_tree(), candidate_root);
            let actual: Vec<_> = scope
                .changes()
                .affected()
                .iter()
                .map(|root| {
                    (
                        root.path().to_vec(),
                        root.domain().to_owned(),
                        root.root(),
                        root.side(),
                        root.properties_changed(),
                    )
                })
                .collect();
            let mut expected = vec![
                (
                    b"/".to_vec(),
                    PUBLIC.to_owned(),
                    candidate_root,
                    RootSide::Candidate,
                    false,
                ),
                (
                    b"/".to_vec(),
                    PUBLIC.to_owned(),
                    prior_root,
                    RootSide::Previous,
                    false,
                ),
                (
                    b"/removed".to_vec(),
                    PUBLIC.to_owned(),
                    child,
                    RootSide::Previous,
                    true,
                ),
            ];
            expected.sort();
            assert_eq!(actual, expected);

            assert!(
                scope
                    .claims()
                    .iter()
                    .any(|claim| claim.path() == b"/removed"
                        && claim.root() == child
                        && claim.side() == RootSide::Previous)
            );
            assert_eq!(
                verify_fixture_scope(&mut history, candidate.identity(), defaults()).unwrap(),
                scope
            );
        }
        assert_eq!(
            history.view_selection(prior.identity()).unwrap(),
            parent_selection
        );
        assert_eq!(
            history.view_selection(candidate.identity()).unwrap(),
            candidate_selection
        );
        assert_eq!(
            verify_fixture_scope(&mut history, prior.identity(), defaults()).unwrap(),
            parent_scope
        );
    }
}
