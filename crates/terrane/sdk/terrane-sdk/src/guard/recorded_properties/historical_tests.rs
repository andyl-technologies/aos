//! Checks ordinary historical calculations and genuinely authenticated core scope dispatch.
//!
//! These fixtures do not replace protected native original-association evidence
//! or qualify certified disclosure cuts and protected historical read workflows.

#![allow(
    clippy::unwrap_used,
    reason = "literal independent fixtures must validate"
)]

use super::*;
use terrane_format::{
    algebra::{MergePolicy, Recipe},
    auth::{self, Authority, Grant, IssuerKey, Request, RequestRoot, Token, Verb, Verbs},
    identity::{IdentityKind, TERRANE_V1},
    properties::semantics::RecordedContext,
    provenance::{Preset, RootSide, VerifiedCommit, sign, sign_authored, verify, verify_history},
    refs::{Commit, CommitContext, Locality},
    tree_format::{EntryKind, LeafItem, Property},
};

mod fixtures;
use fixtures::*;

const MINIMUM: u64 = 262144;

// Fixed historical names, independent of the current compiled registry.
const HISTORICAL: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn graft<'a>(key: &[u8], root: Digest, overrides: Option<Vec<Property<'a>>>) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry: entry(EntryKind::Tree {
            root,
            props: overrides,
        }),
    }
}

#[tokio::test]
async fn historical_root_witnesses_retain_recorded_occurrence_interpretations() {
    for revision in 1..=3 {
        let child = tree(vec![], props(revision));
        let overrides = if revision == 1 {
            Some(vec![Property {
                name: "index-roots",
                value: &[0],
            }])
        } else {
            None
        };
        let root = tree(
            vec![
                graft(b"a", child.0, overrides.clone()),
                graft(b"b", child.0, None),
            ],
            props(revision),
        );
        let store = FixtureStore::new(&[child.clone(), root.clone()]);
        let evidence = TreeEvidence::load_tree(&store, root.0, &[], MINIMUM)
            .await
            .unwrap();
        let input = selected([revision as u8; 32], root.0, revision);
        let mut occurrences = evidence.occurrences(MINIMUM).unwrap();
        occurrences.sort_by(|left, right| left.path.cmp(&right.path));
        assert_eq!(
            occurrences
                .iter()
                .map(|value| (value.root, value.path.clone()))
                .collect::<Vec<_>>(),
            vec![
                (root.0, b"/".to_vec()),
                (child.0, b"/a".to_vec()),
                (child.0, b"/b".to_vec())
            ]
        );
        assert_eq!(occurrences[1].layers[0].0, props(revision));
        assert_eq!(occurrences[1].layers[1].0, props(revision));
        assert_eq!(occurrences[1].layers[1].1, overrides.unwrap_or_default());
        assert!(occurrences[2].layers[1].1.is_empty());
        assert_eq!(
            input
                .historical_roots(&evidence, MINIMUM, defaults())
                .unwrap(),
            vec![
                (b"/".to_vec(), "public".into()),
                (b"/a".to_vec(), "public".into()),
                (b"/b".to_vec(), "public".into())
            ]
        );
        assert_eq!(evidence.nodes[&root.0], root.1);
        assert_eq!(evidence.nodes[&child.0], child.1);
        if revision < 3 {
            assert!(
                SelectedReadInterpretation::Legacy
                    .historical_roots(&evidence, MINIMUM, defaults())
                    .is_err()
            );
        }
    }

    let child = tree(vec![], props(3));
    let root = tree(
        vec![graft(
            b"child",
            child.0,
            Some(vec![Property {
                name: "index-roots",
                value: &[0],
            }]),
        )],
        props(3),
    );
    let evidence = TreeEvidence::load_tree(
        &FixtureStore::new(&[child, root.clone()]),
        root.0,
        &[],
        MINIMUM,
    )
    .await
    .unwrap();
    for revision in [2, 3] {
        assert!(
            selected([9; 32], root.0, revision)
                .historical_roots(&evidence, MINIMUM, defaults())
                .is_err()
        );
    }
    let gaps = tree(vec![], props(2));
    let evidence = TreeEvidence::load_tree(
        &FixtureStore::new(std::slice::from_ref(&gaps)),
        gaps.0,
        &[],
        MINIMUM,
    )
    .await
    .unwrap();
    assert!(
        selected([9; 32], gaps.0, 3)
            .historical_roots(&evidence, MINIMUM, defaults())
            .is_err()
    );
    let untrusted = ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([RecordedAssociation::new(
            [9; 32],
            gaps.0,
            RecordedContext::new(1, 3, &[]).unwrap(),
        )])
        .unwrap(),
    ))
    .select([9; 32], gaps.0)
    .unwrap();
    assert!(
        untrusted
            .historical_roots(&evidence, MINIMUM, defaults())
            .is_err()
    );
    active_binding_placement_controls().await;
    repeated_domain_override_witnesses().await;
}

async fn active_binding_placement_controls() {
    // A complete valid noninherited owner binding distinguishes placement
    // rejection from the malformed active-value controls above.
    let mut binding = head(5, 2);
    for field in [
        text("value"),
        head(5, 1),
        text("uid"),
        text(&"11".repeat(32)),
        text("inherit"),
        vec![0xf4],
    ] {
        binding.extend(field);
    }
    let child = tree(vec![], props(3));
    let mut local = props(3);
    local.push(Property {
        name: "index-roots",
        value: &binding,
    });
    let root = tree(vec![graft(b"child", child.0, None)], local.clone());
    let evidence = TreeEvidence::load_tree(
        &FixtureStore::new(&[child.clone(), root.clone()]),
        root.0,
        &[],
        MINIMUM,
    )
    .await
    .unwrap();
    for revision in [2, 3] {
        let input = selected([9; 32], root.0, revision);
        assert_eq!(
            input
                .historical_roots(&evidence, MINIMUM, defaults())
                .unwrap(),
            vec![
                (b"/".to_vec(), "public".into()),
                (b"/child".to_vec(), "public".into())
            ]
        );
        let occurrences = evidence.occurrences(MINIMUM).unwrap();
        for occurrence in &occurrences {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let policy = input.resolve(&layers, defaults()).unwrap();
            let Some(terrane_format::properties::Value::IndexRoots(roots)) =
                policy.get(terrane_format::properties::PropertyName::IndexRoots)
            else {
                panic!("registered owner-local binding or default remains present")
            };
            assert_eq!(
                roots.get("uid"),
                (occurrence.path == b"/").then_some([0x11; 32])
            );
        }
    }
    let grafted = tree(
        vec![graft(
            b"child",
            child.0,
            Some(vec![Property {
                name: "index-roots",
                value: &binding,
            }]),
        )],
        props(3),
    );
    let evidence = TreeEvidence::load_tree(
        &FixtureStore::new(&[child, grafted.clone()]),
        grafted.0,
        &[],
        MINIMUM,
    )
    .await
    .unwrap();
    for revision in [2, 3] {
        assert!(
            selected([9; 32], grafted.0, revision)
                .historical_roots(&evidence, MINIMUM, defaults())
                .is_err()
        );
    }

    let mut gap = head(5, 2);
    for field in [
        text("value"),
        text(&"00".repeat(32)),
        text("inherit"),
        vec![0xf4],
    ] {
        gap.extend(field);
    }
    let root = tree(
        vec![],
        vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-gaps",
                value: &gap,
            },
        ],
    );
    let evidence = TreeEvidence::load_tree(
        &FixtureStore::new(std::slice::from_ref(&root)),
        root.0,
        &[],
        MINIMUM,
    )
    .await
    .unwrap();
    assert!(
        selected([9; 32], root.0, 3)
            .historical_roots(&evidence, MINIMUM, defaults())
            .is_err()
    );
    assert_eq!(
        selected([9; 32], root.0, 2)
            .historical_roots(&evidence, MINIMUM, defaults())
            .unwrap(),
        vec![(b"/".to_vec(), "public".into())]
    );
}

#[tokio::test]
async fn historical_root_witnesses_use_one_candidate_interpretation_for_prior_comparison() {
    comparison_uses_each_evidence_private_default().await;
    let previous_child = tree(vec![], props(1));
    let previous = tree(vec![graft(b"removed", previous_child.0, None)], props(1));
    let candidate = tree(vec![], props(3));
    let store = FixtureStore::new(&[previous_child, previous.clone(), candidate.clone()]);
    let old = TreeEvidence::load_tree(&store, previous.0, &[], MINIMUM)
        .await
        .unwrap();
    let new = TreeEvidence::load_tree(&store, candidate.0, &[], MINIMUM)
        .await
        .unwrap();
    let table = ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([
            RecordedAssociation::new(
                [1; 32],
                candidate.0,
                RecordedContext::new(1, 3, later(1)).unwrap(),
            ),
            RecordedAssociation::new(
                [2; 32],
                previous.0,
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
            RecordedAssociation::new(
                [3; 32],
                candidate.0,
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        ])
        .unwrap(),
    ));
    let comparison = table.select([1; 32], candidate.0).unwrap();
    assert_eq!(
        comparison
            .historical_roots(&new, MINIMUM, defaults())
            .unwrap(),
        vec![(b"/".to_vec(), "public".into())]
    );
    assert_eq!(
        comparison
            .historical_roots(&old, MINIMUM, defaults())
            .unwrap(),
        vec![
            (b"/".to_vec(), "public".into()),
            (b"/removed".to_vec(), "public".into())
        ]
    );
    assert!(
        table
            .select([2; 32], previous.0)
            .unwrap()
            .historical_roots(&old, MINIMUM, defaults())
            .is_err()
    );
    assert!(
        table
            .select([3; 32], candidate.0)
            .unwrap()
            .historical_roots(&old, MINIMUM, defaults())
            .is_err()
    );
    assert!(table.select([1; 32], previous.0).is_err());
    assert!(table.select([8; 32], candidate.0).is_err());
    assert!(
        ReadInterpretations::Recorded(Arc::new(RecordedAssociations::default()))
            .select([1; 32], candidate.0)
            .is_err()
    );
}

fn expected_context(record: &VerifiedCommit, revision: u64) -> Vec<u8> {
    let mut names = HISTORICAL.to_vec();
    if revision >= 2 {
        names.push("index-roots");
    }
    if revision == 3 {
        names.push("index-gaps");
    }
    names.sort_unstable();
    array(&[
        head(0, 3),
        bytes(&record.identity()),
        text("public"),
        bytes(&array(&[text("preset"), text("any")])),
        vec![0xf6],
        head(0, MINIMUM),
        vec![0xf6],
        array(&[
            bytes(&record.commit().tree),
            head(0, revision),
            array(&names.iter().map(|name| text(name)).collect::<Vec<_>>()),
            array(
                &later(revision)
                    .iter()
                    .map(|name| text(name))
                    .collect::<Vec<_>>(),
            ),
        ]),
    ])
}

#[test]
fn historical_scope_dispatch_preserves_checked_interpretations_and_refusals() {
    nonfresh_checked_scope_comparison();
    original_admin_and_scope_conflict_controls();
    for revision in 1..=3 {
        let (root, wire) = tree(vec![], props(revision));
        let mut base = VerifiedHistory::new(MINIMUM);
        base.insert_tree(root, &[(root, wire)]).unwrap();
        let claims = [RequestRoot {
            path: b"/",
            domain: "public",
        }];
        let record = retain_with_verbs_selected(
            &mut base,
            root,
            vec![],
            "modern ordinary fixture",
            &claims,
            true,
            (
                20,
                terrane_format::properties::selected::Selection::Recorded(
                    RecordedContext::new(revision, 3, later(revision)).unwrap(),
                ),
            ),
        );
        let selected = selected(record.identity(), root, revision);
        let mut history = base.clone();
        let checked = selected
            .verify_original_scope(
                &mut history,
                record.identity(),
                defaults(),
                bootstrap().authority,
                bootstrap(),
            )
            .unwrap();
        assert_eq!(
            checked,
            selected
                .verify_original_scope(
                    &mut history,
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .unwrap()
        );
        let evaluator = selected
            .evaluator(
                &history,
                (record.identity(), root),
                Selector::preset(Preset::Any),
                "public",
                None,
            )
            .unwrap();
        assert_eq!(
            evaluator.canonical_context(),
            expected_context(&record, revision)
        );
        let policy = terrane_format::algebra::TrustContext::from_verified(vec![
            evaluator.clone(),
            evaluator.clone(),
        ])
        .unwrap();
        let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
        let recipe = Recipe::Merge {
            base: root,
            ours: root,
            theirs: root,
            policies: &policies,
            trust: &policy,
            domains: None,
        };
        let expected = expected_context(&record, revision);
        let mut trust = head(5, 4);
        for field in [
            head(0, 1),
            array(&[text("preset"), text("any")]),
            head(0, 2),
            text("terrane-verified-path/v1"),
            head(0, 3),
            array(&[array(&[bytes(&expected), bytes(&expected)]), vec![0xf6]]),
            head(0, 4),
            array(&[]),
        ] {
            trust.extend(field);
        }
        let mut expected_recipe = head(5, 3);
        for field in [
            head(0, 1),
            text("merge"),
            head(0, 2),
            array(&[bytes(&root), bytes(&root), bytes(&root)]),
            head(0, 3),
            head(5, 2),
            text("trust"),
            trust,
            text("policy"),
            array(&[text("prefer-trusted"), text("keep-conflict")]),
        ] {
            expected_recipe.extend(field);
        }
        assert_eq!(recipe.encode(), expected_recipe);
        let mut preimage = b"terrane-memo-v1\0".to_vec();
        preimage.extend_from_slice(&expected_recipe);
        assert_eq!(
            recipe.identity().unwrap(),
            *blake3::hash(&preimage).as_bytes()
        );
        assert!(
            SelectedReadInterpretation::Legacy
                .evaluator(
                    &history,
                    (record.identity(), root),
                    Selector::preset(Preset::Any),
                    "public",
                    None
                )
                .is_err()
        );
        assert!(
            SelectedReadInterpretation::Legacy
                .verify_original_scope(
                    &mut history,
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .is_err()
        );
        assert!(
            selected
                .verify_original_scope(
                    &mut base.clone(),
                    record.identity(),
                    defaults(),
                    "wrong-authority",
                    bootstrap()
                )
                .is_err()
        );
        for bad in [
            OriginalBootstrapPolicy {
                authority: "wrong",
                ..bootstrap()
            },
            OriginalBootstrapPolicy {
                reference: "refs/heads/other",
                ..bootstrap()
            },
            OriginalBootstrapPolicy {
                writer_epoch: 5,
                ..bootstrap()
            },
        ] {
            assert!(
                selected
                    .verify_original_scope(
                        &mut base.clone(),
                        record.identity(),
                        defaults(),
                        bootstrap().authority,
                        bad
                    )
                    .is_err()
            );
        }
        assert!(
            selected
                .verify_original_scope(
                    &mut VerifiedHistory::new(MINIMUM),
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .is_err()
        );
        let wrong = fixtures::selected([8; 32], root, revision);
        assert!(
            wrong
                .verify_original_scope(
                    &mut base.clone(),
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .is_err()
        );
        let wrong_root = fixtures::selected(record.identity(), [8; 32], revision);
        assert!(
            wrong_root
                .verify_original_scope(
                    &mut base.clone(),
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .is_err()
        );
        let mut damaged = record.commit().clone();
        damaged.signature = None;
        assert!(verify_history(&damaged, &keys(), &claims, &[("refs/heads/main", 4)]).is_err());
        let mut damaged = record.commit().clone();
        damaged.provenance.embedded_token = None;
        assert!(verify_history(&damaged, &keys(), &claims, &[("refs/heads/main", 4)]).is_err());
        assert!(
            verify_history(record.commit(), &keys(), &claims, &[("refs/heads/main", 5)]).is_err()
        );
    }
    let (root, wire) = tree(vec![], props(3));
    let mut history = VerifiedHistory::new(MINIMUM);
    history.insert_tree(root, &[(root, wire)]).unwrap();
    let legacy = retain(&mut history, root, vec![], "contextless legacy", &[], false);
    let evaluator = SelectedReadInterpretation::Legacy
        .evaluator(
            &history,
            (legacy.identity(), root),
            Selector::preset(Preset::Any),
            "public",
            None,
        )
        .unwrap();
    assert_eq!(
        evaluator.canonical_context(),
        array(&[
            head(0, 1),
            bytes(&legacy.identity()),
            text("public"),
            bytes(&array(&[text("preset"), text("any")])),
            vec![0xf6],
            head(0, MINIMUM)
        ])
    );
}

fn original_admin_and_scope_conflict_controls() {
    let (root, wire) = tree(
        vec![],
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
    let claims = [RequestRoot {
        path: b"/",
        domain: "public",
    }];
    for mask in [4, 20] {
        let mut history = VerifiedHistory::new(MINIMUM);
        history.insert_tree(root, &[(root, wire.clone())]).unwrap();
        let record = retain_with_verbs_selected(
            &mut history,
            root,
            vec![],
            "fresh original ACL",
            &claims,
            true,
            (
                mask,
                terrane_format::properties::selected::Selection::Recorded(
                    RecordedContext::new(1, 3, later(1)).unwrap(),
                ),
            ),
        );
        let result = selected(record.identity(), root, 1).verify_original_scope(
            &mut history,
            record.identity(),
            defaults(),
            bootstrap().authority,
            bootstrap(),
        );
        assert_eq!(result.is_ok(), mask == 20);
    }

    let (root, wire) = tree(vec![], props(3));
    let mut base = VerifiedHistory::new(MINIMUM);
    base.insert_tree(root, &[(root, wire.clone())]).unwrap();
    let record = retain(
        &mut base,
        root,
        vec![],
        "same scope conflict",
        &claims,
        true,
    );
    let explicit = selected(record.identity(), root, 3);
    let other = selected(record.identity(), root, 2);
    for (first, second) in [
        (&explicit, &other),
        (&other, &explicit),
        (&explicit, &SelectedReadInterpretation::Legacy),
        (&SelectedReadInterpretation::Legacy, &explicit),
    ] {
        let mut history = VerifiedHistory::new(MINIMUM);
        history.insert_tree(root, &[(root, wire.clone())]).unwrap();
        let freshly_checked = retain_with_verbs_selected(
            &mut history,
            root,
            vec![],
            "same scope conflict",
            &claims,
            true,
            (20, first.selection()),
        );
        assert_eq!(freshly_checked.identity(), record.identity());
        let checked = first
            .verify_original_scope(
                &mut history,
                record.identity(),
                defaults(),
                bootstrap().authority,
                bootstrap(),
            )
            .unwrap();
        assert!(
            second
                .verify_original_scope(
                    &mut history,
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .is_err()
        );
        assert_eq!(
            first
                .verify_original_scope(
                    &mut history,
                    record.identity(),
                    defaults(),
                    bootstrap().authority,
                    bootstrap()
                )
                .unwrap(),
            checked
        );
        assert!(
            first
                .evaluator(
                    &history,
                    (record.identity(), root),
                    Selector::preset(Preset::Any),
                    "public",
                    None
                )
                .is_ok()
        );
    }
}

fn nonfresh_checked_scope_comparison() {
    let child = tree(vec![], props(1));
    let parent_tree = tree(vec![graft(b"removed", child.0, None)], props(1));
    let candidate_tree = tree(vec![], props(1));
    let mut history = VerifiedHistory::new(MINIMUM);
    for (root, wire) in [child.clone(), parent_tree.clone(), candidate_tree.clone()] {
        history.insert_tree(root, &[(root, wire)]).unwrap();
    }
    let claims = [
        RequestRoot {
            path: b"/",
            domain: "public",
        },
        RequestRoot {
            path: b"/removed",
            domain: "public",
        },
    ];
    let parent = retain_with_verbs_selected(
        &mut history,
        parent_tree.0,
        vec![],
        "retained parent",
        &claims,
        true,
        (
            20,
            terrane_format::properties::selected::Selection::Recorded(
                RecordedContext::new(1, 3, later(1)).unwrap(),
            ),
        ),
    );
    let parent_input = selected(parent.identity(), parent_tree.0, 1);
    parent_input
        .verify_original_scope(
            &mut history,
            parent.identity(),
            defaults(),
            bootstrap().authority,
            bootstrap(),
        )
        .unwrap();
    let candidate = retain_with_verbs_selected(
        &mut history,
        candidate_tree.0,
        vec![parent.identity()],
        "removed occurrence",
        &claims,
        true,
        (
            20,
            terrane_format::properties::selected::Selection::Recorded(
                RecordedContext::new(1, 3, later(1)).unwrap(),
            ),
        ),
    );
    let candidate_input = selected(candidate.identity(), candidate_tree.0, 1);
    let scope = candidate_input
        .verify_original_scope(
            &mut history,
            candidate.identity(),
            defaults(),
            bootstrap().authority,
            bootstrap(),
        )
        .unwrap();
    assert!(!scope.changes().fresh());
    assert_eq!(scope.changes().first_parent(), Some(parent.identity()));
    assert_eq!(scope.changes().candidate_tree(), candidate_tree.0);
    let complete = scope
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
        .collect::<Vec<_>>();
    let mut expected = vec![
        (
            b"/".to_vec(),
            "public".into(),
            candidate_tree.0,
            RootSide::Candidate,
            false,
        ),
        (
            b"/".to_vec(),
            "public".into(),
            parent_tree.0,
            RootSide::Previous,
            false,
        ),
        (
            b"/removed".to_vec(),
            "public".into(),
            child.0,
            RootSide::Previous,
            true,
        ),
    ];
    expected.sort();
    assert_eq!(complete, expected);
    let evaluator = candidate_input
        .evaluator(
            &history,
            (candidate.identity(), candidate_tree.0),
            Selector::preset(Preset::Any),
            "public",
            None,
        )
        .unwrap();
    assert_eq!(
        evaluator.canonical_context(),
        expected_context(&candidate, 1)
    );
    assert!(
        selected(candidate.identity(), candidate_tree.0, 3)
            .verify_original_scope(
                &mut history,
                candidate.identity(),
                defaults(),
                bootstrap().authority,
                bootstrap()
            )
            .is_err()
    );
    assert_eq!(
        candidate_input
            .verify_original_scope(
                &mut history,
                candidate.identity(),
                defaults(),
                bootstrap().authority,
                bootstrap()
            )
            .unwrap(),
        scope
    );
}
