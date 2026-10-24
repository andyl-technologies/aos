//! Exercises explicit interpretations through actual complete certificate verification.
//!
//! Ordinary caller configuration is independent of signed claims. No test
//! manufactures root-scope, disclosure, provisional or native authority flags.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::algebra::{MergePolicy, Recipe};
use crate::properties::selected::Selection;
use crate::properties::semantics::{
    RecordedContext,
    associations::{RecordedAssociation, RecordedAssociations},
};

mod fixtures;
use fixtures::*;

fn candidate<'a>(
    history: &VerifiedHistory,
    record: &VerifiedCommit,
    input: &RecordedAssociations,
) -> Result<DisclosureCandidate<'a>, Rejected> {
    DisclosureCandidate::new_with_recorded_properties_and_bootstrap(
        history,
        record.identity(),
        &[authority()],
        defaults(),
        Some(input),
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )
}

fn check_scope(
    history: &mut VerifiedHistory,
    record: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) {
    let input = association(record, revision, later);
    assert_eq!(
        history.property_selection(record.identity()).unwrap(),
        Selection::Recorded(input.context().clone())
    );
    VerifiedRootScope::verify_with_recorded_properties_and_bootstrap(
        history,
        record.identity(),
        defaults(),
        Some(&input),
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )
    .unwrap();
}

fn ordinary_public() -> (VerifiedHistory, VerifiedCommit) {
    let (root, bytes) = root_tree(vec![item(b"other", file())], PUBLIC);
    let mut current = receipt(root, EntryOrigin::Current);
    current.path = b"other".to_vec();
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.profile_pair.entry_receipts = Some(vec![current]);
    let record = reverified(authored(commit, PUBLIC, &[9; 32], true));
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history
        .insert_commit_selected(
            record.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();
    (history, record)
}

// The complete destination embeds a real ordinary source, not a guessed checked
// scope or a private cut source relabeled as a public producer.
fn with_dependency(
    fixture: &RecordedFixture,
    dependency: &VerifiedCommit,
    source: &VerifiedHistory,
) -> (VerifiedHistory, VerifiedCommit) {
    let disclosed = fixture
        .history
        .entry(&EntryLocation {
            commit: fixture.commit.identity(),
            root: fixture.leaf,
            path: b"file".to_vec(),
        })
        .unwrap();
    let (root, bytes) = tree(
        vec![item(b"file", disclosed), item(b"other", file())],
        Some(properties(3)),
    );
    let mut history = source.clone();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = fixture.commit.commit().clone();
    commit.tree = root;
    commit.parents = vec![
        dependency.identity(),
        fixture.source.source_commit.identity(),
    ];
    let certificate = &mut commit.profile_pair.entry_receipts.as_mut().unwrap()[0];
    certificate.root = root;
    let mut other = receipt(
        root,
        EntryOrigin::Source(EntrySource {
            commit: dependency.identity(),
            root: dependency.commit().tree,
            path: b"other".to_vec(),
        }),
    );
    other.path = b"other".to_vec();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .push(other);
    let signed = certify(&fixture.source, commit);
    history
        .insert_commit_selected(
            signed.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();
    (history, signed)
}

#[test]
fn recorded_disclosure_preserves_selected_view_interpretations_and_actual_occurrences() {
    for revision in 1..=3 {
        let fixture = fixture_recorded(revision, true);
        let input = table(&fixture.commit, revision, later(revision));
        let (history, batch) = candidate(&fixture.history, &fixture.commit, &input)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(batch.view(), fixture.commit.identity());
        assert_eq!(batch.boundaries().len(), 1);
        let boundary = &batch.boundaries()[0];
        assert_eq!(
            boundary.root_occurrences(),
            &[b"/a/inner".to_vec(), b"/b/inner".to_vec()]
        );
        assert_eq!(boundary.target_domain(), PUBLIC);
        assert_eq!(boundary.target().root, fixture.leaf);
        assert_eq!(boundary.target().path, b"file");
        assert_eq!(boundary.authority_repository(), authority().repository);
        assert_eq!(boundary.authority_key(), &authority().public_key);
        assert_eq!(boundary.authority_domain(), SOURCE_DOMAIN);
        assert_eq!(boundary.observed_at(), 100);
        assert_eq!(
            boundary.original_introducer(),
            fixture.source.source_commit.identity()
        );
        assert_eq!(boundary.source().root, fixture.source.source_root);
        assert_eq!(
            boundary.source().commit,
            fixture.source.source_commit.identity()
        );
        assert_eq!(boundary.source().path, b"file");
        assert_eq!(
            boundary.destination_binding(),
            disclosure_target_binding(fixture.commit.commit()).unwrap()
        );
        assert!(
            history
                .commit(&fixture.source.source_commit.identity())
                .is_none()
        );
        let scope = history.root_scopes.get(&fixture.commit.identity()).unwrap();
        assert!(
            scope.matches_properties(Some(
                input
                    .select(fixture.commit.identity(), fixture.commit.commit().tree)
                    .unwrap()
            ))
        );
        assert!(!scope.matches_properties(None));
        assert!(scope.changes().fresh());
        assert_eq!(scope.changes().affected().len(), 5);
        assert_eq!(scope.claims().len(), 1);
        assert_eq!(scope.claims()[0].path(), b"/");

        let selected = evaluator(&history, &fixture.commit, revision, later(revision));
        let expected = context(&fixture.commit, Some(revision), later(revision));
        assert_eq!(selected.canonical_context(), expected);
        assert_eq!(vocabulary(revision).len(), 32 + revision as usize);
        assert!(selected.accepts_path(b"a/inner/file"));
        assert!(selected.accepts_path(b"b/inner/file"));
        assert!(!selected.accepts(fixture.leaf, b"file"));
        assert_eq!(
            selected.producer_time(fixture.commit.commit().tree, b"a/inner/file"),
            Some(100)
        );
        assert!(
            TrustContext::new_with_recorded(
                &history,
                fixture.commit.identity(),
                Selector::preset(Preset::Any),
                PUBLIC,
                Some("baseline"),
                None,
            )
            .is_err()
        );
        let (location, layers) = history
            .locate_policy_layers(fixture.commit.identity(), b"b/inner/file")
            .unwrap();
        assert_eq!(location.root, fixture.leaf);
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[1].occurrence, b"b");
        assert_eq!(layers[2].occurrence, b"b/inner");
        assert_eq!(layers[1].overrides.as_ref().unwrap()[0].name, "trust");
        for layer in layers {
            let raw: Vec<_> = layer
                .properties
                .iter()
                .map(|property| (property.name, property.value))
                .collect();
            if revision == 1 {
                assert!(raw.contains(&("index-roots", &[0][..])));
            }
            if revision < 3 {
                assert!(raw.contains(&("index-gaps", &[0][..])));
            }
        }

        let trust =
            crate::algebra::TrustContext::from_verified(vec![selected.clone(), selected.clone()])
                .unwrap();
        let roots = fixture.commit.commit().tree;
        let recipe_model = Recipe::Merge {
            base: roots,
            ours: roots,
            theirs: roots,
            policies: &[MergePolicy::PreferTrusted, MergePolicy::KeepConflict],
            trust: &trust,
            domains: None,
        };
        let (expected_recipe, expected_preimage, key) =
            recipe(&fixture.commit, &[expected.clone(), expected]);
        assert_eq!(recipe_model.encode(), expected_recipe);
        assert_eq!(recipe_model.identity().unwrap(), key);
        assert_eq!(&expected_preimage[..16], b"terrane-memo-v1\0");
        let freshly_finished = finish(&fixture, revision, later(revision)).unwrap().0;
        let fresh = evaluator(
            &freshly_finished,
            &fixture.commit,
            revision,
            later(revision),
        );
        let rebound = Recipe::decode(&expected_recipe)
            .unwrap()
            .bind_verified(vec![fresh.clone(), fresh])
            .unwrap();
        assert_eq!(rebound.as_recipe().encode(), expected_recipe);
        assert_eq!(rebound.as_recipe().identity().unwrap(), key);
    }

    // The exact same signed physical root is independently interpreted in two
    // views, and even explicit current semantics cannot alias legacy config.
    let fixture = fixture_recorded(3, false);
    let legacy_input = fixture
        .history
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            fixture.commit.identity(),
            Selection::Legacy,
        )]))
        .unwrap();
    assert_eq!(
        legacy_input
            .property_selection(fixture.commit.identity())
            .unwrap(),
        Selection::Legacy
    );
    let (legacy_history, _) = disclosed_candidate(
        &legacy_input,
        fixture.commit.identity(),
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    let legacy = TrustContext::new(
        &legacy_history,
        fixture.commit.identity(),
        Selector::preset(Preset::Any),
        PUBLIC,
        Some("baseline"),
    )
    .unwrap();
    assert_eq!(
        legacy.canonical_context(),
        context(&fixture.commit, None, &[])
    );
    let explicit_history = finish(&fixture, 3, &[]).unwrap().0;
    let explicit = evaluator(&explicit_history, &fixture.commit, 3, &[]);
    assert_ne!(legacy.canonical_context(), explicit.canonical_context());
    let legacy_key = recipe(
        &fixture.commit,
        &[
            context(&fixture.commit, None, &[]),
            context(&fixture.commit, None, &[]),
        ],
    )
    .2;
    let explicit_key = recipe(
        &fixture.commit,
        &[
            context(&fixture.commit, Some(3), &[]),
            context(&fixture.commit, Some(3), &[]),
        ],
    )
    .2;
    assert_ne!(legacy_key, explicit_key);

    let mut changed = fixture.commit.commit().clone();
    changed.message = "same physical root, another view".to_string();
    let other = certify(&fixture.source, changed);
    assert_eq!(other.commit().tree, fixture.commit.commit().tree);
    assert_ne!(other.identity(), fixture.commit.identity());
    let mut history = fixture
        .history
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            fixture.commit.identity(),
            Selection::Recorded(
                RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
            ),
        )]))
        .unwrap();
    history
        .insert_commit_selected(
            other.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();
    let inputs = RecordedAssociations::new([
        association(&fixture.commit, 1, &["index-roots", "index-gaps"]),
        association(&other, 3, &[]),
    ])
    .unwrap();
    let first = candidate(&history, &fixture.commit, &inputs)
        .unwrap()
        .finish()
        .unwrap()
        .0;
    let second = candidate(&history, &other, &inputs)
        .unwrap()
        .finish()
        .unwrap()
        .0;
    assert_eq!(
        evaluator(&first, &fixture.commit, 1, &["index-roots", "index-gaps"]).canonical_context(),
        context(&fixture.commit, Some(1), &["index-roots", "index-gaps"])
    );
    assert_eq!(
        evaluator(&second, &other, 3, &[]).canonical_context(),
        context(&other, Some(3), &[])
    );

    let owner_binding = map(vec![
        (text("inherit"), vec![0xf4]),
        (
            text("value"),
            map(vec![(text("uid"), text(&"20".repeat(32)))]),
        ),
    ]);
    let (owner_history, owner) = namespace_metadata(&fixture, "index-roots", &owner_binding, false);
    for revision in [2, 3] {
        let selected_history = owner_history
            .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                owner.identity(),
                Selection::Recorded(RecordedContext::new(revision, 3, &[]).unwrap()),
            )]))
            .unwrap();
        assert!(
            candidate(&selected_history, &owner, &table(&owner, revision, &[]))
                .unwrap()
                .finish()
                .is_ok()
        );
    }
    assert!(
        disclosed_candidate(&owner_history, owner.identity(), &[authority()], defaults())
            .unwrap()
            .finish()
            .is_ok()
    );
    let (graft_history, graft) = namespace_metadata(&fixture, "index-roots", &owner_binding, true);
    let inert_graft_history = graft_history
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            graft.identity(),
            Selection::Recorded(RecordedContext::new(1, 3, &["index-roots"]).unwrap()),
        )]))
        .unwrap();
    assert!(
        candidate(
            &inert_graft_history,
            &graft,
            &table(&graft, 1, &["index-roots"])
        )
        .unwrap()
        .finish()
        .is_ok()
    );
    for revision in [2, 3] {
        let behavioral_history = graft_history
            .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                graft.identity(),
                Selection::Recorded(RecordedContext::new(revision, 3, &[]).unwrap()),
            )]))
            .unwrap();
        assert!(candidate(&behavioral_history, &graft, &table(&graft, revision, &[])).is_err());
    }
    // The old merged projection accepts the same complete binding as if it were
    // namespace-owned. The actual current witness must refuse its graft role
    // before certificate authentication, not wait for final root verification.
    let (_, merged) = inert_graft_history
        .locate_policies(graft.identity(), b"docs/file")
        .unwrap();
    let layers: Vec<_> = merged
        .iter()
        .map(|properties| crate::properties::RootLayer {
            properties,
            overrides: &[],
        })
        .collect();
    assert!(crate::properties::resolve(&layers, defaults()).is_ok());
    assert!(
        disclosed_candidate(&graft_history, graft.identity(), &[authority()], defaults()).is_err()
    );
    let gap_binding = map(vec![
        (text("inherit"), vec![0xf4]),
        (text("value"), text(&"30".repeat(32))),
    ]);
    for on_graft in [false, true] {
        let (history, record) = namespace_metadata(&fixture, "index-gaps", &gap_binding, on_graft);
        let inert_history = history
            .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                record.identity(),
                Selection::Recorded(RecordedContext::new(2, 3, &["index-gaps"]).unwrap()),
            )]))
            .unwrap();
        assert!(
            candidate(&inert_history, &record, &table(&record, 2, &["index-gaps"]))
                .unwrap()
                .finish()
                .is_ok()
        );
        assert!(candidate(&history, &record, &table(&record, 3, &[])).is_err());
        assert!(
            disclosed_candidate(&history, record.identity(), &[authority()], defaults()).is_err()
        );
    }
}

#[test]
fn recorded_disclosure_refuses_missing_associations_and_conflicting_dependency_scopes() {
    let fixture = fixture_recorded(3, false);
    let empty = RecordedAssociations::default();
    let wrong_view = RecordedAssociations::new([RecordedAssociation::new(
        [0; 32],
        fixture.commit.commit().tree,
        RecordedContext::new(3, 3, &[]).unwrap(),
    )])
    .unwrap();
    let wrong_root = RecordedAssociations::new([RecordedAssociation::new(
        fixture.commit.identity(),
        [0; 32],
        RecordedContext::new(3, 3, &[]).unwrap(),
    )])
    .unwrap();
    for input in [None, Some(&empty), Some(&wrong_view), Some(&wrong_root)] {
        assert!(
            DisclosureCandidate::new_with_recorded_properties(
                &fixture.history,
                fixture.commit.identity(),
                &[authority()],
                defaults(),
                input
            )
            .is_err()
        );
        assert!(
            DisclosureCandidate::new_with_recorded_properties_and_bootstrap(
                &fixture.history,
                fixture.commit.identity(),
                &[authority()],
                defaults(),
                input,
                fixture_bootstrap().authority,
                fixture_bootstrap()
            )
            .is_err()
        );
    }
    assert!(RecordedContext::new(0, 3, &[]).is_err());
    assert!(RecordedContext::new(4, 3, &[]).is_err());
    assert!(RecordedContext::new(1, 3, &["index-roots", "index-roots"]).is_err());
    assert!(RecordedContext::new(3, 3, &["index-gaps"]).is_err());
    let inert = fixture_recorded(1, true);
    assert!(finish(&inert, 1, &[]).is_err());
    assert!(finish(&inert, 2, &["index-gaps"]).is_err());
    assert!(finish(&inert, 3, &[]).is_err());

    let input = table(&fixture.commit, 3, &[]);
    assert!(
        DisclosureCandidate::new_with_recorded_properties(
            &fixture.history,
            fixture.commit.identity(),
            &[authority()],
            defaults(),
            Some(&input)
        )
        .unwrap()
        .finish()
        .is_err()
    );
    let wrong_bootstrap = OriginalBootstrapPolicy {
        writer_epoch: 5,
        ..fixture_bootstrap()
    };
    assert!(
        DisclosureCandidate::new_with_recorded_properties_and_bootstrap(
            &fixture.history,
            fixture.commit.identity(),
            &[authority()],
            defaults(),
            Some(&input),
            fixture_bootstrap().authority,
            wrong_bootstrap
        )
        .is_err()
    );

    let (raw, public) = ordinary_public();
    let mut current = raw
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            public.identity(),
            Selection::Active,
        )]))
        .unwrap();
    verify_fixture_scope(&mut current, public.identity(), defaults()).unwrap();
    let mut recorded_one = raw
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            public.identity(),
            Selection::Recorded(
                RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
            ),
        )]))
        .unwrap();
    check_scope(
        &mut recorded_one,
        &public,
        1,
        &["index-roots", "index-gaps"],
    );
    let mut recorded_three = raw
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            public.identity(),
            Selection::Recorded(RecordedContext::new(3, 3, &[]).unwrap()),
        )]))
        .unwrap();
    check_scope(&mut recorded_three, &public, 3, &[]);
    let mut different_names = raw
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            public.identity(),
            Selection::Recorded(RecordedContext::new(3, 3, &["future.marker"]).unwrap()),
        )]))
        .unwrap();
    check_scope(&mut different_names, &public, 3, &["future.marker"]);
    for (left, right) in [
        (&current, &recorded_three),
        (&recorded_one, &recorded_three),
        (&recorded_three, &different_names),
    ] {
        for (receiver, incoming) in [(left, right), (right, left)] {
            let mut merged = receiver.clone();
            let before = merged.root_scopes.clone();
            assert!(merged.append_verified(incoming).is_err());
            assert_eq!(merged.root_scopes, before);
        }
    }

    let dependency_raw = raw
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            public.identity(),
            Selection::Recorded(
                RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
            ),
        )]))
        .unwrap();
    let (history, destination) = with_dependency(&fixture, &public, &dependency_raw);
    let missing_dependency = table(&destination, 3, &[]);
    assert!(
        candidate(&history, &destination, &missing_dependency)
            .unwrap()
            .finish()
            .is_err()
    );
    let inputs = RecordedAssociations::new([
        association(&destination, 3, &[]),
        association(&public, 1, &["index-roots", "index-gaps"]),
    ])
    .unwrap();
    // Only raw ordinarily authenticated input is initially available. The actual
    // dependency verifier must consume that dependency's own explicit entry.
    let mut staged = candidate(&history, &destination, &inputs).unwrap();
    assert_eq!(staged.required_commits(), &[public.identity()]);
    staged
        .validate_dependency_scope_with_bootstrap(
            public.identity(),
            fixture_bootstrap().authority,
            fixture_bootstrap(),
        )
        .unwrap();
    let finished = staged.finish().unwrap().0;
    assert!(
        finished.root_scopes[&public.identity()].matches_properties(Some(
            inputs
                .select(public.identity(), public.commit().tree)
                .unwrap()
        ))
    );
    assert!(
        finished.root_scopes[&destination.identity()].matches_properties(Some(
            inputs
                .select(destination.identity(), destination.commit().tree)
                .unwrap()
        ))
    );
    assert!(
        !finished.root_scopes[&destination.identity()]
            .changes()
            .fresh()
    );
    for imported in [&current, &recorded_three, &different_names] {
        let mut staged = candidate(&history, &destination, &inputs).unwrap();
        assert!(staged.insert_history(imported).is_err());
        assert!(staged.finish().is_err());
        let mut staged = candidate(&history, &destination, &inputs).unwrap();
        assert!(staged.insert_history(imported).is_err());
        assert!(staged.validate_dependency_scope(public.identity()).is_err());
    }
    let mut staged = candidate(&history, &destination, &inputs).unwrap();
    staged.insert_history(&recorded_one).unwrap();
    assert!(staged.finish().is_ok());
    let before = raw.root_scopes.clone();
    let mut staged = candidate(&history, &destination, &inputs).unwrap();
    assert!(staged.insert_history(&raw).is_err());
    assert_eq!(raw.root_scopes, before);
    assert!(
        staged
            .validate_dependency_scope(destination.identity())
            .is_err()
    );

    // A genuine fresh materialization still requires Admin when its ACL widens
    // the independently supplied baseline, even with a valid certificate.
    let acl = array(&[array(&[text(PUBLIC), uint(4)])]);
    let (history, record) = namespace_metadata(&fixture, "acl", &acl, false);
    for revision in [1, 3] {
        let history = history
            .fixture_with_selections(&alloc::collections::BTreeMap::from([(
                record.identity(),
                Selection::Recorded(RecordedContext::new(revision, 3, later(revision)).unwrap()),
            )]))
            .unwrap();
        let inputs = table(&record, revision, later(revision));
        assert!(
            candidate(&history, &record, &inputs)
                .unwrap()
                .finish()
                .is_err()
        );

        let baseline_acl = [(PUBLIC, 4)];
        let bootstrap = OriginalBootstrapPolicy {
            acl: &baseline_acl,
            ..fixture_bootstrap()
        };
        let finished = DisclosureCandidate::new_with_recorded_properties_and_bootstrap(
            &history,
            record.identity(),
            &[authority()],
            defaults(),
            Some(&inputs),
            bootstrap.authority,
            bootstrap,
        )
        .unwrap()
        .finish()
        .unwrap()
        .0;
        assert!(
            finished.root_scopes[&record.identity()]
                .changes()
                .required_admin()
                .is_empty()
        );
    }
}

#[test]
fn recorded_disclosure_keeps_certificate_binding_public_retention_and_attribute_producer_checks() {
    let fixture = fixture_recorded(3, false);
    let input = table(&fixture.commit, 3, &[]);
    for configured in [
        vec![],
        vec![DisclosureAuthority {
            repository: "",
            ..authority()
        }],
        vec![DisclosureAuthority {
            domain: "private:wrong",
            ..authority()
        }],
        vec![DisclosureAuthority {
            public_key: [0; 32],
            ..authority()
        }],
        vec![DisclosureAuthority {
            not_before: 101,
            ..authority()
        }],
        vec![DisclosureAuthority {
            not_after: Some(100),
            ..authority()
        }],
        vec![
            authority(),
            DisclosureAuthority {
                repository: "different physical repository",
                ..authority()
            },
        ],
    ] {
        assert!(
            DisclosureCandidate::new_with_recorded_properties(
                &fixture.history,
                fixture.commit.identity(),
                &configured,
                defaults(),
                Some(&input)
            )
            .is_err()
        );
    }
    for change in 0..5 {
        let mut commit = fixture.commit.commit().clone();
        match change {
            0 => commit.message.push_str(" altered"),
            1 => {
                commit.profile_pair.entry_receipts.as_mut().unwrap()[0]
                    .disclosure_proof
                    .as_mut()
                    .unwrap()
                    .signature[0] ^= 1
            }
            2 => {
                commit.profile_pair.entry_receipts.as_mut().unwrap()[0]
                    .disclosure_proof
                    .as_mut()
                    .unwrap()
                    .observed_at = 99
            }
            3 => {
                commit.profile_pair.entry_receipts.as_mut().unwrap()[0]
                    .reintroduced_from
                    .as_mut()
                    .unwrap()
                    .path = b"secret".to_vec()
            }
            _ => {
                commit.profile_pair.entry_receipts.as_mut().unwrap()[0]
                    .disclosure_proof
                    .as_mut()
                    .unwrap()
                    .source_domain = "private:wrong".to_string()
            }
        }
        let record = reverified(authored(commit, PUBLIC, &[11; 32], false));
        let mut history = fixture.history.clone();
        history
            .insert_commit_selected(
                record.clone(),
                crate::properties::selected::Selection::Recorded(
                    RecordedContext::new(3, 3, &[]).unwrap(),
                ),
            )
            .unwrap();
        assert!(
            candidate(&history, &record, &table(&record, 3, &[])).is_err(),
            "mutation {change}"
        );
    }
    let mut unsigned = fixture.commit.commit().clone();
    unsigned.signature = None;
    assert!(
        verify_history(
            &unsigned,
            &issuer_keys(),
            &[RequestRoot {
                path: b"/",
                domain: PUBLIC
            }],
            &[("refs/heads/main", 4)]
        )
        .is_err()
    );
    let mut wrong_epoch = fixture.commit.commit().clone();
    wrong_epoch.provenance.writer_epoch = 5;
    assert!(
        verify_history(
            &wrong_epoch,
            &issuer_keys(),
            &[RequestRoot {
                path: b"/",
                domain: PUBLIC
            }],
            &[("refs/heads/main", 4)]
        )
        .is_err()
    );

    // A Directory has a supported marker projection, distinct from this signed
    // file projection; a canonical Conflict has no supported disclosure
    // projection. Both records retain genuine final Commit signatures.
    let disclosed = fixture
        .history
        .entry(&EntryLocation {
            commit: fixture.commit.identity(),
            root: fixture.leaf,
            path: b"file".to_vec(),
        })
        .unwrap();
    for kind in [
        EntryKind::Directory { mode: 0o755 },
        EntryKind::Conflict {
            candidates: vec![file(), entry(b"inert-target")],
            base: None,
        },
    ] {
        let mut changed = disclosed.clone();
        changed.kind = kind;
        let (root, bytes) = tree(vec![item(b"file", changed)], Some(properties(3)));
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history.insert_tree(root, &[(root, bytes)]).unwrap();
        let mut commit = fixture.commit.commit().clone();
        commit.tree = root;
        commit.profile_pair.entry_receipts.as_mut().unwrap()[0].root = root;
        let record = certify(&fixture.source, commit);
        history
            .insert_commit_selected(
                record.clone(),
                crate::properties::selected::Selection::Recorded(
                    RecordedContext::new(3, 3, &[]).unwrap(),
                ),
            )
            .unwrap();
        assert!(candidate(&history, &record, &table(&record, 3, &[])).is_err());
    }

    // A private first-parent cut requires complete explicit public origins.
    let mut cut = fixture.commit.commit().clone();
    cut.parents = vec![fixture.source.source_commit.identity()];
    let cut = certify(&fixture.source, cut);
    let mut history = fixture.history.clone();
    history
        .insert_commit_selected(
            cut.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();
    let (finished, batch) = candidate(&history, &cut, &table(&cut, 3, &[]))
        .unwrap()
        .finish()
        .unwrap();
    assert!(batch.certified_parent(cut.identity(), fixture.source.source_commit.identity()));
    assert!(finished.root_scopes[&cut.identity()].changes().fresh());
    assert!(
        finished
            .commit(&fixture.source.source_commit.identity())
            .is_none()
    );
    let mut with_private = history.clone();
    with_private
        .append_evidence(&fixture.source.source)
        .unwrap();
    let (still_public, _) = candidate(&with_private, &cut, &table(&cut, 3, &[]))
        .unwrap()
        .finish()
        .unwrap();
    let strict = TrustContext::new_with_recorded(
        &still_public,
        cut.identity(),
        Selector::preset(Preset::Strict),
        PUBLIC,
        Some("baseline"),
        Some((
            cut.identity(),
            cut.commit().tree,
            RecordedContext::new(3, 3, &[]).unwrap(),
        )),
    )
    .unwrap();
    assert!(!strict.accepts_path(b"file"));

    for attributes in [
        None,
        Some(vec![(
            "provenance.reintroduced-from".to_string(),
            EntryOrigin::Source(EntrySource {
                commit: fixture.source.source_commit.identity(),
                root: fixture.source.source_root,
                path: b"file".to_vec(),
            }),
        )]),
    ] {
        let mut commit = cut.commit().clone();
        commit.profile_pair.entry_receipts.as_mut().unwrap()[0].attributes = attributes;
        let record = certify(&fixture.source, commit);
        let mut history = fixture.history.clone();
        history
            .insert_commit_selected(
                record.clone(),
                crate::properties::selected::Selection::Recorded(
                    RecordedContext::new(3, 3, &[]).unwrap(),
                ),
            )
            .unwrap();
        assert!(candidate(&history, &record, &table(&record, 3, &[])).is_err());
    }

    // Every complete publicly retained record matters, including an unrelated
    // private subtree, ordinary ancestor and unselected receipt source.
    for edge in [
        PrivateRetention::SiblingGraft,
        PrivateRetention::OrdinaryAncestor,
        PrivateRetention::UnselectedOrigin,
    ] {
        let (retained, public) = retained_private(&fixture.source, edge);
        let (history, destination) = with_dependency(&fixture, &public, &retained);
        let inputs = RecordedAssociations::new([
            association(&destination, 3, &[]),
            association(&public, 3, &[]),
            association(&fixture.source.source_commit, 3, &[]),
        ])
        .unwrap();
        let staged = candidate(&history, &destination, &inputs).unwrap();
        assert!(staged.finish().is_err(), "private retention {edge:?}");
    }

    // Reissuing the genuine file certificate cannot cover an unrelated sibling
    // or turn a private source edge into the exact permitted audit-only cut.
    for mode in 0..3 {
        let (root, bytes) = tree(
            vec![item(b"file", disclosed.clone()), item(b"other", file())],
            Some(properties(3)),
        );
        let mut commit = cut.commit().clone();
        commit.tree = root;
        let receipts = commit.profile_pair.entry_receipts.as_mut().unwrap();
        receipts[0].root = root;
        if mode != 0 {
            let origin = if mode == 1 {
                EntryOrigin::Current
            } else {
                EntryOrigin::Source(EntrySource {
                    commit: fixture.source.source_commit.identity(),
                    root: fixture.source.source_root,
                    path: b"file".to_vec(),
                })
            };
            let mut sibling = receipt(root, origin);
            sibling.path = b"other".to_vec();
            receipts.push(sibling);
        }
        let record = certify(&fixture.source, commit);
        let mut history = fixture.history.clone();
        history.insert_tree(root, &[(root, bytes)]).unwrap();
        history
            .insert_commit_selected(
                record.clone(),
                crate::properties::selected::Selection::Recorded(
                    RecordedContext::new(3, 3, &[]).unwrap(),
                ),
            )
            .unwrap();
        assert!(candidate(&history, &record, &table(&record, 3, &[])).is_err());
    }
}
