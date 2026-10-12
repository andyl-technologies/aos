//! Checks completed native repeated occurrences and ancestor-first exact policy layers.

use super::*;

#[tokio::test]
async fn native_recorded_selection_completed_grafts_retain_one_view_context_and_distinct_local_layers()
-> Result {
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&legacy, first.commit).await?;
    let location = Location::capture(&legacy, first.commit).await?;
    drop(session);
    drop(legacy);

    let later = ["index-gaps", "index-roots"];
    let historical = location
        .reopen(
            1,
            1,
            &later,
            vec![ViewSelection::new(
                first.commit,
                first_root,
                Selection::Legacy,
                1,
            )?],
        )
        .await?;
    let mut session = historical.begin(REFERENCE, &token(), "sdk").await?;
    let (proposal, child_root) = support::grafted_later_request(vec![first.commit])?;
    let root = proposal.commit.tree;
    let second = historical.commit_request(&mut session, proposal).await?;
    let published = lineage(&historical).await?;
    let expected = [
        Expected::legacy(first.commit, first_root),
        Expected::recorded(second.commit, root, 1, 1, &later),
    ];
    assert_contexts(&published.used, &expected)?;
    let actual = completed(&historical, second.commit).await?;
    assert_contexts(&actual, &expected)?;
    let view = actual
        .views
        .iter()
        .find(|view| view.view == second.commit)
        .ok_or("missing actual completed graft view")?;
    assert_eq!(view.roots.len(), 3);
    let parent = view
        .roots
        .iter()
        .find(|root| root.path == b"/")
        .ok_or("missing original namespace")?;
    let left = view
        .roots
        .iter()
        .find(|root| root.path == b"/left")
        .ok_or("missing left occurrence")?;
    let right = view
        .roots
        .iter()
        .find(|root| root.path == b"/right")
        .ok_or("missing right occurrence")?;
    assert_eq!(parent.root, root);
    assert_eq!(left.root, child_root);
    assert_eq!(right.root, child_root);
    assert_eq!(parent.layers.len(), 1);
    assert_eq!(left.layers.len(), 2);
    assert_eq!(right.layers.len(), 2);
    assert_eq!(left.layers[0], parent.layers[0]);
    assert_eq!(right.layers[0], parent.layers[0]);
    assert_eq!(left.layers[1].properties, parent.layers[0].properties);
    assert_eq!(right.layers[1].properties, parent.layers[0].properties);
    assert_eq!(parent.layers[0].overrides, b"\xa0");
    assert_eq!(left.layers[1].overrides, b"\xa1\x66retain\x67forever");
    assert_eq!(right.layers[1].overrides, b"\xa1\x66retain\x62gc");
    assert_ne!(left.layers[1].overrides, right.layers[1].overrides);
    assert_eq!(
        historical.coordinator().store().ref_get(REFERENCE).await?,
        Some(second)
    );
    Ok(())
}
