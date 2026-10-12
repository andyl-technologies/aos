//! Checks exact mixed selections through genuine complete disclosure verification.
//!
//! Ordinary profile inputs never replace signed history, scoped certificate keys,
//! original bootstrap or complete dependency verification. No native publication
//! or required-index coverage result follows from this pure prerequisite.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::properties::semantics::{
    RecordedContext,
    associations::{Error, RecordedAssociation, RecordedAssociations},
    selections::{ViewPropertySelection, ViewPropertySelections},
};
use crate::properties::{PropertyName, RootLayer};

mod fixtures;
use fixtures::{association, finish, fixture, valid_later_binding_fixture};

#[test]
fn mixed_selection_keeps_legacy_parent_and_recorded_candidate() {
    let fixture = fixture(false);
    let current = association(&fixture.candidate, 3, &[]);
    let legacy = ViewPropertySelection::Legacy {
        view: fixture.parent.identity(),
        original_root: fixture.parent.commit().tree,
    };
    let input = ViewPropertySelections::legacy([
        legacy.clone(),
        legacy,
        ViewPropertySelection::Recorded(current.clone()),
    ])
    .unwrap();

    assert_eq!(
        input.select(fixture.parent.identity(), fixture.parent.commit().tree),
        Ok(None)
    );
    assert_eq!(
        input.select(
            fixture.candidate.identity(),
            fixture.candidate.commit().tree
        ),
        Ok(Some(&current))
    );
    assert_eq!(input.select([82; 32], [83; 32]), Ok(None));
    assert_eq!(current.revision(), 3);
    assert!(current.later_registered().is_empty());
    assert!(input.select(fixture.parent.identity(), [81; 32]).is_err());
}

#[test]
fn mixed_selection_keeps_recorded_one_inert_names() {
    let fixture = fixture(true);
    let parent = association(&fixture.parent, 1, &["index-roots", "index-gaps"]);
    let input = ViewPropertySelections::legacy([
        ViewPropertySelection::Recorded(parent.clone()),
        ViewPropertySelection::Recorded(association(&fixture.candidate, 3, &[])),
    ])
    .unwrap();
    let selected = input
        .select(fixture.parent.identity(), fixture.parent.commit().tree)
        .unwrap()
        .unwrap();
    let original = fixture.parent_properties.clone();
    let effective = selected
        .with_context(|context| {
            context.resolve(
                &[RootLayer {
                    properties: &fixture.parent_properties,
                    overrides: &[],
                }],
                disclosure::defaults(),
            )
        })
        .unwrap()
        .unwrap();

    assert_eq!(selected, &parent);
    assert_eq!(selected.revision(), 1);
    assert_eq!(
        selected.later_registered(),
        &["index-gaps".to_string(), "index-roots".to_string()]
    );
    assert!(effective.get(PropertyName::IndexRoots).is_none());
    assert!(effective.get(PropertyName::IndexGaps).is_none());
    assert_eq!(fixture.parent_properties, original);
    assert!(
        RecordedContext::new(3, 3, &[])
            .unwrap()
            .validate_map(&original)
            .is_err()
    );
    assert!(RecordedContext::new(4, 3, &[]).is_err());
}

#[test]
fn mixed_selection_requires_recorded_ancestor_mapping() {
    let fixture = fixture(false);
    let current = association(&fixture.candidate, 3, &[]);
    let input =
        ViewPropertySelections::recorded(RecordedAssociations::new([current.clone()]).unwrap(), [])
            .unwrap();

    assert_eq!(
        input.select(fixture.parent.identity(), fixture.parent.commit().tree),
        Err(Error::MissingView {
            view: fixture.parent.identity()
        })
    );
    assert!(finish(&fixture, &input).is_err());
    let explicit = ViewPropertySelections::recorded(
        RecordedAssociations::new([current.clone()]).unwrap(),
        [ViewPropertySelection::Legacy {
            view: fixture.parent.identity(),
            original_root: fixture.parent.commit().tree,
        }],
    )
    .unwrap();
    assert_eq!(
        explicit.select(fixture.parent.identity(), fixture.parent.commit().tree),
        Ok(None)
    );
    assert!(finish(&fixture, &explicit).is_ok());
    let empty = ViewPropertySelections::recorded(RecordedAssociations::default(), []).unwrap();
    assert!(
        empty
            .select(
                fixture.candidate.identity(),
                fixture.candidate.commit().tree
            )
            .is_err()
    );
}

#[test]
fn mixed_selection_refuses_conflicting_view_or_root() {
    let view = [61; 32];
    let root = [62; 32];
    let recorded = RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
    );
    let same = ViewPropertySelection::Recorded(recorded.clone());
    let legacy = ViewPropertySelection::Legacy {
        view,
        original_root: root,
    };
    let changed_root = ViewPropertySelection::Legacy {
        view,
        original_root: [63; 32],
    };
    let revision = ViewPropertySelection::Recorded(RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(3, 3, &[]).unwrap(),
    ));
    let later = ViewPropertySelection::Recorded(RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(1, 3, &["index-roots"]).unwrap(),
    ));
    for changed in [legacy.clone(), changed_root.clone(), revision, later] {
        assert_eq!(
            ViewPropertySelections::legacy([same.clone(), changed.clone()]),
            Err(Error::ConflictingView { view })
        );
        assert_eq!(
            ViewPropertySelections::legacy([changed.clone(), same.clone()]),
            Err(Error::ConflictingView { view })
        );
        assert!(
            ViewPropertySelections::recorded(
                RecordedAssociations::new([recorded.clone()]).unwrap(),
                [changed]
            )
            .is_err()
        );
    }
    assert_eq!(
        ViewPropertySelections::legacy([legacy.clone(), changed_root]),
        Err(Error::ConflictingView { view })
    );
    let accepted = ViewPropertySelections::recorded(
        RecordedAssociations::new([recorded.clone()]).unwrap(),
        [same.clone(), same],
    )
    .unwrap();
    assert_eq!(accepted.select(view, root), Ok(Some(&recorded)));
    assert_eq!(
        accepted.select(view, [64; 32]),
        Err(Error::OriginalRootMismatch {
            view,
            expected: root,
            actual: [64; 32]
        })
    );
    assert_eq!(
        ViewPropertySelections::recorded(
            RecordedAssociations::new([recorded]).unwrap(),
            [ViewPropertySelection::Legacy {
                view,
                original_root: [63; 32]
            }]
        ),
        Err(Error::OriginalRootMismatch {
            view,
            expected: root,
            actual: [63; 32]
        })
    );
}

#[test]
fn mixed_selection_distinguishes_shared_root_view_contexts() {
    let root = [71; 32];
    let one = RecordedAssociation::new(
        [72; 32],
        root,
        RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
    );
    let two = RecordedAssociation::new(
        [73; 32],
        root,
        RecordedContext::new(2, 3, &["index-gaps"]).unwrap(),
    );
    let three = RecordedAssociation::new([74; 32], root, RecordedContext::new(3, 3, &[]).unwrap());
    let input = ViewPropertySelections::recorded(
        RecordedAssociations::new([one.clone()]).unwrap(),
        [
            ViewPropertySelection::Recorded(two.clone()),
            ViewPropertySelection::Recorded(three.clone()),
            ViewPropertySelection::Legacy {
                view: [75; 32],
                original_root: root,
            },
        ],
    )
    .unwrap();

    for expected in [&one, &two, &three] {
        assert_eq!(input.select(expected.view(), root), Ok(Some(expected)));
    }
    assert_eq!(input.select([75; 32], root), Ok(None));
    assert_eq!(
        input.select([76; 32], root),
        Err(Error::MissingView { view: [76; 32] })
    );
    assert!(input.select(two.view(), [77; 32]).is_err());
}

#[test]
fn mixed_disclosure_finishes_with_legacy_dependency() {
    let fixture = fixture(false);
    let current = association(&fixture.candidate, 3, &[]);
    let input =
        ViewPropertySelections::legacy([ViewPropertySelection::Recorded(current.clone())]).unwrap();
    let (history, batch) = finish(&fixture, &input).unwrap();

    assert_completed(&fixture, &history, &batch);
    assert!(history.root_scopes[&fixture.parent.identity()].matches_properties(None));
    assert!(history.root_scopes[&fixture.candidate.identity()].matches_properties(Some(&current)));
    let without_bootstrap = DisclosureCandidate::new_with_property_selections(
        &history,
        fixture.candidate.identity(),
        &[disclosure::authority()],
        disclosure::defaults(),
        &input,
    )
    .unwrap()
    .finish()
    .unwrap();
    assert_eq!(
        without_bootstrap.1.required_commits(),
        batch.required_commits()
    );
    assert_completed(&fixture, &without_bootstrap.0, &without_bootstrap.1);

    let uniform =
        RecordedAssociations::new([current, association(&fixture.parent, 3, &[])]).unwrap();
    assert!(
        DisclosureCandidate::new_with_recorded_properties(
            &history,
            fixture.candidate.identity(),
            &[disclosure::authority()],
            disclosure::defaults(),
            Some(&uniform)
        )
        .unwrap()
        .finish()
        .is_err()
    );
}

#[test]
fn mixed_disclosure_finishes_with_recorded_one_dependency() {
    let fixture = valid_later_binding_fixture();
    let parent = association(&fixture.parent, 1, &["index-roots", "index-gaps"]);
    let current = association(&fixture.candidate, 3, &[]);
    let input = ViewPropertySelections::recorded(
        RecordedAssociations::new([parent.clone()]).unwrap(),
        [ViewPropertySelection::Recorded(current.clone())],
    )
    .unwrap();
    let original = fixture.parent_properties.clone();
    assert_eq!(
        original
            .iter()
            .find(|property| property.name == "index-roots")
            .unwrap()
            .value,
        b"\xa2\x65value\xa0\x67inherit\xf4",
    );
    assert!(
        !original
            .iter()
            .any(|property| property.name == "index-gaps")
    );
    let effective = parent
        .with_context(|context| {
            context.resolve(
                &[RootLayer {
                    properties: &original,
                    overrides: &[],
                }],
                disclosure::defaults(),
            )
        })
        .unwrap()
        .unwrap();
    assert!(effective.get(PropertyName::IndexRoots).is_none());
    assert!(
        RecordedContext::new(3, 3, &[])
            .unwrap()
            .validate_map(&original)
            .is_ok()
    );
    assert!(
        RootChangePlan::derive_with_properties(
            &fixture.history,
            fixture.candidate.commit(),
            disclosure::defaults(),
            &RecordedContext::new(3, 3, &[]).unwrap(),
        )
        .is_ok()
    );

    let (history, batch) = finish(&fixture, &input).unwrap();

    assert_completed(&fixture, &history, &batch);
    assert_eq!(fixture.parent_properties, original);
    assert!(history.root_scopes[&fixture.parent.identity()].matches_properties(Some(&parent)));
    assert!(history.root_scopes[&fixture.candidate.identity()].matches_properties(Some(&current)));
    let mut changed = fixture_bootstrap();
    changed.writer_epoch += 1;
    assert!(
        DisclosureCandidate::new_with_property_selections_and_bootstrap(
            &fixture.history,
            fixture.candidate.identity(),
            &[disclosure::authority()],
            disclosure::defaults(),
            &input,
            changed.authority,
            changed
        )
        .is_err()
    );
    assert!(
        DisclosureCandidate::new_with_property_selections_and_bootstrap(
            &fixture.history,
            fixture.candidate.identity(),
            &[],
            disclosure::defaults(),
            &input,
            fixture_bootstrap().authority,
            fixture_bootstrap()
        )
        .is_err()
    );
}

#[test]
fn mixed_disclosure_refuses_scope_mode_substitution() {
    let fixture = fixture(false);
    let candidate = association(&fixture.candidate, 3, &[]);
    let correct =
        ViewPropertySelections::legacy([ViewPropertySelection::Recorded(candidate.clone())])
            .unwrap();
    let (history, _) = finish(&fixture, &correct).unwrap();
    let before = history.root_scopes.clone();
    let wrong_parent = ViewPropertySelections::legacy([
        ViewPropertySelection::Recorded(candidate.clone()),
        ViewPropertySelection::Recorded(association(&fixture.parent, 3, &[])),
    ])
    .unwrap();
    let wrong_candidate = ViewPropertySelections::legacy([]).unwrap();

    assert!(
        DisclosureCandidate::new_with_property_selections(
            &history,
            fixture.candidate.identity(),
            &[disclosure::authority()],
            disclosure::defaults(),
            &wrong_parent
        )
        .unwrap()
        .finish()
        .is_err()
    );
    assert!(
        DisclosureCandidate::new_with_property_selections(
            &history,
            fixture.candidate.identity(),
            &[disclosure::authority()],
            disclosure::defaults(),
            &wrong_candidate
        )
        .is_err()
    );
    assert_eq!(history.root_scopes, before);
    let wrong_root = ViewPropertySelections::legacy([ViewPropertySelection::Recorded(
        RecordedAssociation::new(
            fixture.candidate.identity(),
            [92; 32],
            RecordedContext::new(3, 3, &[]).unwrap(),
        ),
    )])
    .unwrap();
    assert!(
        DisclosureCandidate::new_with_property_selections(
            &fixture.history,
            fixture.candidate.identity(),
            &[disclosure::authority()],
            disclosure::defaults(),
            &wrong_root
        )
        .is_err()
    );
}

fn assert_completed(
    fixture: &fixtures::MixedFixture,
    history: &VerifiedHistory,
    batch: &VerifiedDisclosureBatch,
) {
    assert_eq!(batch.view(), fixture.candidate.identity());
    assert_eq!(batch.required_commits(), &[fixture.parent.identity()]);
    assert_eq!(batch.boundaries().len(), 1);
    assert!(batch.certified_parent(
        fixture.candidate.identity(),
        fixture.source.source_commit.identity()
    ));
    assert!(
        history
            .commit(&fixture.source.source_commit.identity())
            .is_none()
    );
    let target = EntryLocation {
        commit: fixture.candidate.identity(),
        root: fixture.candidate.commit().tree,
        path: b"file".to_vec(),
    };
    assert_eq!(
        history.introducing_commit(&target),
        Ok(fixture.candidate.identity())
    );
    let ordinary = EntryLocation {
        path: b"other".to_vec(),
        ..target
    };
    assert_eq!(
        history.introducing_commit(&ordinary),
        Ok(fixture.parent.identity())
    );
    let boundary = &batch.boundaries()[0];
    assert_eq!(boundary.source().root, fixture.source.source_root);
    assert_eq!(
        boundary.original_introducer(),
        fixture.source.source_commit.identity()
    );
    assert_eq!(boundary.root_occurrences(), &[b"/".to_vec()]);
    assert_eq!(boundary.target_domain(), "public");
}
