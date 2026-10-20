//! Checks independently owned immutable per-view table configuration against real signed views.

use super::*;

#[tokio::test]
async fn native_recorded_selection_owned_table_distinguishes_signed_views_sharing_one_root()
-> Result {
    let original = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = original.begin(REFERENCE, &token(), "sdk").await?;
    let first = original
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let second = original
        .commit_request(&mut session, request(vec![first.commit]))
        .await?;
    let root = signed_root(&original, first.commit).await?;
    assert_eq!(signed_root(&original, second.commit).await?, root);
    assert_ne!(first.commit, second.commit);
    let location = Location::capture(&original, second.commit).await?;
    drop(session);
    drop(original);

    let first_selection = {
        let mut owned = [String::from("index-roots"), String::from("é.future")];
        let selection = {
            let names = owned.iter().map(String::as_str).collect::<Vec<_>>();
            selected(first.commit, root, 1, 1, &names)?
        };
        owned[0].clear();
        owned[1].clear();
        selection
    };
    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![
                first_selection.clone(),
                first_selection,
                selected(second.commit, root, 2, 1, &["index-gaps"])?,
            ],
        )
        .await?;
    drop(location);
    let expected = [
        Expected::recorded(first.commit, root, 1, 1, &["index-roots", "é.future"]),
        Expected::recorded(second.commit, root, 2, 1, &["index-gaps"]),
    ];
    assert_contexts(&completed(&repository, second.commit).await?, &expected)?;
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second)
    );
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_each_conflicting_input_refuses_without_replacing_original_table()
-> Result {
    use terrane_format::properties::semantics::RecordedContext;

    let repository = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let root = signed_root(&repository, first.commit).await?;
    let location = Location::capture(&repository, first.commit).await?;
    let before = lineage(&repository).await?;
    let base = selected(first.commit, root, 1, 1, &["index-roots", "é.future"])?;
    for (name, conflicting) in [
        (
            "root",
            selected(first.commit, [8; 32], 1, 1, &["index-roots", "é.future"])?,
        ),
        (
            "revision",
            selected(first.commit, root, 2, 1, &["é.future"])?,
        ),
        (
            "current revision",
            ViewSelection::new(
                first.commit,
                root,
                Selection::Recorded(RecordedContext::new(1, 2, &["index-roots", "é.future"])?),
                1,
            )?,
        ),
        (
            "later names",
            selected(first.commit, root, 1, 1, &["index-roots"])?,
        ),
        (
            "attribute",
            selected(first.commit, root, 1, 2, &["index-roots", "é.future"])?,
        ),
        (
            "mode",
            ViewSelection::new(first.commit, root, Selection::Legacy, 1)?,
        ),
    ] {
        let result = location
            .reopen(3, 2, &[], vec![base.clone(), conflicting])
            .await;
        let error = result
            .err()
            .ok_or_else(|| format!("conflicting {name} installed"))?;
        let failure = error
            .downcast_ref::<crate::store::StoreFailure>()
            .ok_or("lost typed conflict refusal")?;
        assert!(
            matches!(
                failure.kind(),
                StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
            ),
            "{name}"
        );
        assert_eq!(
            repository.coordinator().store().ref_get(REFERENCE).await?,
            Some(first.clone()),
            "{name}"
        );
        assert_eq!(lineage(&repository).await?, before, "{name}");
    }
    let independently_valid = location.reopen(3, 2, &[], vec![base]).await?;
    assert_contexts(
        &completed(&independently_valid, first.commit).await?,
        &[Expected::recorded(
            first.commit,
            root,
            1,
            1,
            &["index-roots", "é.future"],
        )],
    )?;
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_missing_head_cannot_be_recovered_from_actual_context_bearing_ack()
-> Result {
    let original = crate::guard::recorded_native_fixture::fixture(true).await?;
    let mut session = original.begin(REFERENCE, &token(), "sdk").await?;
    let first = original
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let root = signed_root(&original, first.commit).await?;
    let before = lineage(&original).await?;
    assert_contexts(
        &before.used,
        &[Expected::recorded(first.commit, root, 3, 2, &[])],
    )?;
    let location = Location::capture(&original, first.commit).await?;
    drop(session);
    drop(original);

    let repository = location.reopen(3, 2, &[], Vec::new()).await?;
    let authority = repository
        .coordinator()
        .guard()
        .original_commit(&first.commit)?
        .baseline()
        .authority()
        .clone();
    {
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        let guard = repository
            .coordinator()
            .guard()
            .held_guard(holder.destination(), TokioClock)?;
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        consumed.registration(&authority)?;
        let error = guard
            .verified_history_observed(
                first.commit,
                HistoryObservation::held(observed.identity()).tracked(&consumed),
            )
            .await
            .err()
            .ok_or(
                "persisted key7 or global current selection filled the absent head association",
            )?;
        assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty()
        );
        let trace = consumed.finish()?;
        assert!(trace.views.is_empty());
        assert_eq!(trace.view_interpretations, Some(Vec::new()));
        assert_eq!(
            destination.selected_lineage(&observed, REFERENCE).await?,
            Some(before.encode()?)
        );
        observed.revalidate().await?;
    }
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(first)
    );
    Ok(())
}
