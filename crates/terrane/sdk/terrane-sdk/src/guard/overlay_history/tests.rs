//! Exercises borrowed overlay completion through genuine native publication and reads.

#![allow(
    clippy::unwrap_used,
    reason = "Isolated native assertions intentionally panic."
)]

mod cancellation;
mod fixture;
mod fs;
mod physical;
mod scope;

use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::ref_advance::tests::token;
use crate::store::{RefStore, TokioClock};
use fixture::{Fixture, REFERENCE, TestResult};
use terrane_format::auth::Verb;

#[tokio::test]
async fn overlay_history_borrows_historical_layer_and_shares_only_one_walk() -> TestResult {
    let fixture = Fixture::open().await?;
    let observation = fixture.guard().store().observe_content_for_tests();
    let mut previous = None;
    for _ in 0..2 {
        let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
        let source = holder.source();
        let selected = source.observe_publication_ordinary_retained().await?;
        let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
        let authority = fixture.guard().configured_original_authority()?;
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        let history_scope = HistoryObservation::held(selected.identity()).tracked(&consumed);
        let initial = guard
            .authorize_observed(
                REFERENCE,
                &token(),
                Verb::Read,
                &[b"/".to_vec()],
                "sdk",
                history_scope,
            )
            .await?;
        assert_eq!(initial.record(), Some(&fixture.current));
        let layer_consumed = ConsumedResolver::new(&guard, &authority)?;
        let layer_scope = HistoryObservation::held(selected.identity()).tracked(&layer_consumed);
        observation.reset();
        fixture.fs.reset();
        let (tree, history) = guard
            .verified_overlay_layer_history_observed(fixture.layer.commit, layer_scope)
            .await?;
        let counts = observation.snapshot();
        let paths = fixture.fs.native_paths();
        assert_eq!(tree.commit.identity(), fixture.layer.commit);
        assert_eq!(tree.evidence.root, fixture.layer.root);
        assert_eq!(history.commits().count(), 2);
        assert_eq!(history.commit(&fixture.layer.commit), Some(&tree.commit));
        assert!(history.commit(&fixture.base.commit).is_some());
        assert!(history.commit(&fixture.current.commit).is_none());
        let completed = layer_consumed.observed_completed_view_contexts_for_tests()?;
        assert_eq!(completed.len(), 2);
        assert!(
            completed
                .iter()
                .any(|context| context.view == fixture.layer.commit
                    && context.original_root == fixture.layer.root)
        );
        assert!(counts.commit_gets >= 3);
        assert!(counts.node_gets >= 3);
        let packs = paths
            .iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .collect::<Vec<_>>();
        assert!(!packs.is_empty());
        let mut commit_pack = None;
        let mut root_pack = None;
        for pack in &packs {
            let bytes = tokio::fs::read(pack).await?;
            let reader = crate::pack::PackReader::open(&bytes)?;
            if reader
                .entries()
                .iter()
                .any(|entry| entry.hash() == &fixture.layer.commit)
            {
                assert!(commit_pack.replace(*pack).is_none());
            }
            if reader
                .entries()
                .iter()
                .any(|entry| entry.hash() == &fixture.layer.root)
            {
                assert!(root_pack.replace(*pack).is_none());
            }
        }
        assert!(
            commit_pack.is_some(),
            "the actual signed layer pack must be measured"
        );
        assert!(
            root_pack.is_some(),
            "the actual canonical layer root pack must be measured"
        );
        for pack in packs
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
        {
            assert_eq!(packs.iter().filter(|path| **path == pack).count(), 1);
        }
        if let Some((earlier_counts, earlier_paths)) = &previous {
            assert_eq!(&counts, earlier_counts);
            assert_eq!(&paths, earlier_paths);
        }
        previous = Some((counts, paths));
        let final_authority = guard
            .authorize_observed(
                REFERENCE,
                &token(),
                Verb::Read,
                &[b"/".to_vec()],
                "sdk",
                history_scope,
            )
            .await?;
        assert_eq!(final_authority.record(), Some(&fixture.current));
        selected.revalidate().await?;
    }
    assert_eq!(
        fixture.guard().store().ref_get(REFERENCE).await?,
        Some(fixture.current.clone())
    );
    Ok(())
}
