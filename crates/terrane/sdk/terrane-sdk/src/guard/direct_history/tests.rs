//! Checks tokenless immutable history against genuine native publication and exclusions.

#![allow(
    clippy::unwrap_used,
    reason = "Isolated fixture assertions intentionally panic."
)]

mod cancellation;
mod configuration;
mod fixture;
mod fs;
mod physical;

use crate::guard::HistoryObservation;
use crate::store::RefStore;
use fixture::{Fixture, REFERENCE, TestResult, at_stage};
use terrane_format::provenance::VerifiedHistory;

/// Selects the two genuine tokenless entry points under regression.
#[derive(Clone, Copy, Debug)]
enum Mode {
    History,
    TreeAndHistory,
}

impl Mode {
    async fn verify(self, fixture: &Fixture) -> TestResult<VerifiedHistory> {
        self.verify_guard(fixture.guard(), fixture.head.commit)
            .await
    }

    async fn verify_guard<S: crate::store::Store, C: crate::store::Clock>(
        self,
        guard: &crate::guard::Guard<S, C>,
        target: terrane_format::identity::Digest,
    ) -> TestResult<VerifiedHistory> {
        match self {
            Self::History => Ok(guard
                .verified_history_observed(target, HistoryObservation::default())
                .await?),
            Self::TreeAndHistory => {
                let (tree, history) = guard
                    .verified_tree_history_observed(target, HistoryObservation::default())
                    .await?;
                assert_eq!(tree.commit.identity(), target);
                assert_eq!(tree.evidence.root, tree.commit.commit().tree);
                assert_eq!(
                    history
                        .commit(&target)
                        .ok_or("target history absent")?
                        .commit()
                        .tree,
                    tree.evidence.root
                );
                Ok(history)
            }
        }
    }
}

#[tokio::test]
async fn direct_history_verifies_historical_target_with_fresh_walks_in_both_modes() -> TestResult {
    let fixture = Fixture::open().await?;
    assert_ne!(fixture.head.commit, fixture.current.commit);
    assert_eq!(
        fixture.guard().configured_current,
        crate::guard::history::completion::InterpretationSelection::Active
    );
    for (view, revision, attribute_revision) in
        [(fixture.head.commit, 1, 1), (fixture.current.commit, 3, 2)]
    {
        let phase = if view == fixture.head.commit {
            "preliminary H tree"
        } else {
            "preliminary N tree"
        };
        let root = at_stage(phase, fixture.guard().verified_tree(view).await)?
            .evidence
            .root;
        let (selection, profile) = fixture
            .guard()
            .selected_view_context_for_tests(view, root)?;
        let terrane_format::properties::selected::Selection::Recorded(context) = selection else {
            panic!("published Recorded selection was lost");
        };
        assert_eq!(context.revision(), revision);
        assert_eq!(context.current_revision(), 3);
        assert_eq!(profile.attribute_revision, attribute_revision);
    }
    let observation = fixture.guard().store().observe_content_for_tests();
    for mode in [Mode::History, Mode::TreeAndHistory] {
        observation.reset();
        fixture.fs.reset();
        let first = at_stage(
            match mode {
                Mode::History => "first History walk",
                Mode::TreeAndHistory => "first TreeAndHistory walk",
            },
            mode.verify(&fixture).await,
        )?;
        let first_counts = observation.snapshot();
        let first_data = fixture.fs.native_paths();
        observation.reset();
        fixture.fs.reset();
        let second = at_stage(
            match mode {
                Mode::History => "second History walk",
                Mode::TreeAndHistory => "second TreeAndHistory walk",
            },
            mode.verify(&fixture).await,
        )?;
        let second_counts = observation.snapshot();
        let second_data = fixture.fs.native_paths();
        for history in [&first, &second] {
            assert!(history.commit(&fixture.base.commit).is_some());
            assert_eq!(
                history
                    .commit(&fixture.head.commit)
                    .ok_or("target absent")?
                    .commit()
                    .tree,
                fixture.target_root
            );
            assert_eq!(history.commits().count(), 2);
            assert!(history.commit(&fixture.current.commit).is_none());
        }
        assert!(
            first_counts.commit_gets >= 2,
            "{mode:?}: both canonical signed commits must be read"
        );
        assert!(
            first_counts.node_gets >= 2,
            "{mode:?}: both canonical trees must be read"
        );
        assert_eq!(
            first_counts, second_counts,
            "{mode:?}: separate invocations must repeat the full walk"
        );
        assert_eq!(
            first_data, second_data,
            "{mode:?}: native DATA cannot outlive one walk"
        );
        let packs = first_data
            .iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .collect::<Vec<_>>();
        assert!(!packs.is_empty());
        for pack in packs
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
        {
            assert_eq!(
                packs.iter().filter(|path| **path == pack).count(),
                1,
                "{mode:?}: a containing pack supplies immutable DATA once per walk"
            );
        }
        assert_eq!(
            fixture.guard().store().ref_get(REFERENCE).await?,
            Some(fixture.current.clone())
        );
    }
    Ok(())
}

#[tokio::test]
async fn direct_history_retains_genuine_legacy_historical_control() -> TestResult {
    let fixture = Fixture::legacy().await?;
    let (selection, profile) = fixture
        .guard()
        .selected_view_context_for_tests(fixture.head.commit, fixture.target_root)?;
    assert_eq!(
        selection,
        terrane_format::properties::selected::Selection::Legacy
    );
    assert_eq!(profile.attribute_revision, 1);
    for mode in [Mode::History, Mode::TreeAndHistory] {
        let history = mode.verify(&fixture).await?;
        assert_eq!(history.commits().count(), 2);
        assert!(history.commit(&fixture.current.commit).is_none());
    }
    Ok(())
}
