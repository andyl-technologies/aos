//! Refuses real foreign borrowed inputs and ordinary reinterpretation of a whiteout.

use super::*;

#[tokio::test]
async fn overlay_history_refuses_foreign_holder_resolver_configuration_and_ordinary_scope()
-> TestResult {
    let fixture = Fixture::open().await?;
    let foreign = Fixture::open().await?;
    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let selected = source.observe_publication_ordinary_retained().await?;
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let foreign_holder = SingleHeld::acquire_read_only(foreign.guard().store()).await?;
    let foreign_source = foreign_holder.source();
    let foreign_selected = foreign_source
        .observe_publication_ordinary_retained()
        .await?;
    let authority = fixture.guard().configured_original_authority()?;
    let foreign_authority = foreign.guard().configured_original_authority()?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    let wrong_resolver = ConsumedResolver::new(foreign.guard(), &foreign_authority)?;
    for scope in [
        HistoryObservation::held(foreign_selected.identity()).tracked(&consumed),
        HistoryObservation::held(selected.identity()).tracked(&wrong_resolver),
    ] {
        assert!(
            guard
                .verified_overlay_layer_history_observed(fixture.layer.commit, scope)
                .await
                .is_err()
        );
    }
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    assert!(
        wrong_resolver
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );

    let mut substituted = fixture.guard().held_guard(holder.source(), TokioClock)?;
    substituted.keys.clear();
    let configured = ConsumedResolver::new(&guard, &authority)?;
    assert!(
        substituted
            .verified_overlay_layer_history_observed(
                fixture.layer.commit,
                HistoryObservation::held(selected.identity()).tracked(&configured)
            )
            .await
            .is_err()
    );
    assert!(
        configured
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );

    let mut changed_current = fixture.guard().held_guard(holder.source(), TokioClock)?;
    changed_current.configured_current =
        crate::guard::history::completion::InterpretationSelection::Active;
    let changed_configuration = ConsumedResolver::new(&changed_current, &authority)?;
    assert!(
        changed_current
            .verified_overlay_layer_history_observed(
                fixture.layer.commit,
                HistoryObservation::held(selected.identity()).tracked(&changed_configuration)
            )
            .await
            .is_err()
    );
    assert!(
        changed_configuration
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );

    let ordinary = ConsumedResolver::new(&guard, &authority)?;
    assert!(
        guard
            .verified_history_observed(
                fixture.layer.commit,
                HistoryObservation::held(selected.identity()).tracked(&ordinary)
            )
            .await
            .is_err()
    );
    assert!(
        ordinary
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    let overlay = ConsumedResolver::new(&guard, &authority)?;
    let (tree, _) = guard
        .verified_overlay_layer_history_observed(
            fixture.layer.commit,
            HistoryObservation::held(selected.identity()).tracked(&overlay),
        )
        .await?;
    assert_eq!(tree.evidence.root, fixture.layer.root);
    assert!(
        !overlay
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn overlay_history_rechecks_current_read_after_revocation() -> TestResult {
    use crate::ref_advance::tests::request_file_acl;
    use crate::store::StoreErrorKind;

    let fixture = Fixture::open().await?;
    {
        let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
        let source = holder.source();
        let selected = source.observe_publication_ordinary_retained().await?;
        let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
        let authority = fixture.guard().configured_original_authority()?;
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        let scope = HistoryObservation::held(selected.identity()).tracked(&consumed);
        let current = guard
            .authorize_observed(
                REFERENCE,
                &token(),
                Verb::Read,
                &[b"/".to_vec()],
                "sdk",
                scope,
            )
            .await?;
        assert_eq!(current.record(), Some(&fixture.current));
        guard
            .verified_overlay_layer_history_observed(fixture.layer.commit, scope)
            .await?;
    }
    let mut writer = fixture.repository.begin(REFERENCE, &token(), "sdk").await?;
    let revoked = fixture
        .repository
        .commit_request(
            &mut writer,
            request_file_acl(vec![fixture.current.commit], b"revoked current policy", 0),
        )
        .await?;
    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let selected = source.observe_publication_ordinary_retained().await?;
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let authority = fixture.guard().configured_original_authority()?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    let failure = guard
        .authorize_observed(
            REFERENCE,
            &token(),
            Verb::Read,
            &[b"/".to_vec()],
            "sdk",
            HistoryObservation::held(selected.identity()).tracked(&consumed),
        )
        .await
        .err()
        .ok_or("earlier layer verification retained current Read")?;
    assert!(
        matches!(failure.kind(), StoreErrorKind::Denied { verb: "read", pattern } if pattern == REFERENCE)
    );
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(revoked));
    Ok(())
}

#[tokio::test]
async fn overlay_history_captured_invocations_cannot_exchange_purpose_or_reader() -> TestResult {
    use crate::guard::overlay_history::{
        CheckedOverlayHistoryInputs, OverlayHistoryStore, OverlayPurpose, OverlayReadCheck,
    };

    let fixture = Fixture::open().await?;
    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let selected = source.observe_publication_ordinary_retained().await?;
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let authority = fixture.guard().configured_original_authority()?;
    let authenticated = ConsumedResolver::new(&guard, &authority)?;
    let (tree, _) = guard
        .verified_overlay_layer_history_observed(
            fixture.layer.commit,
            HistoryObservation::held(selected.identity()).tracked(&authenticated),
        )
        .await?;
    assert_eq!(tree.evidence.root, fixture.layer.root);

    // Retain only genuine configured Original records. These input receipts
    // grant neither completion nor actor rights to the two new invocations.
    let configured = ConsumedResolver::new(&guard, &authority)?;
    configured.registration(&authority)?;
    let originals = guard
        .original_commits
        .read()
        .map_err(|_| "fixture Original map poisoned")?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for original in &originals {
        configured.original(original)?;
    }
    let pins = configured.control_pins()?;
    let registration = pins
        .iter()
        .find(|pin| pin.key == "registration.cbor")
        .ok_or("genuine registration pin absent")?
        .clone();
    let mut controls = fixture
        .guard()
        .hold_original_registration(&authority, selected.identity())
        .await?;
    let retained = controls.retain_used(&pins).await?;
    guard.retain_original_controls(&retained)?;
    let guard_record = source
        .selected_guard_snapshot_record_retained(&selected)
        .await?
        .ok_or("actual selected Guard record absent")?;
    let first = ConsumedResolver::new(&guard, &authority)?;
    let second = ConsumedResolver::new(&guard, &authority)?;
    first.registration(&authority)?;
    second.registration(&authority)?;
    assert_eq!(
        guard_record.bytes(),
        Some(first.snapshot_bytes()?.as_slice())
    );
    assert_eq!(first.snapshot_bytes()?, second.snapshot_bytes()?);
    let first_scope = HistoryObservation::held(selected.identity())
        .tracked(&first)
        .overlay_layer(tree.commit.identity(), tree.evidence.root);
    let second_scope = HistoryObservation::held(selected.identity())
        .tracked(&second)
        .overlay_layer(tree.commit.identity(), tree.evidence.root);
    let first_check = OverlayReadCheck::capture(
        fixture.layer.commit,
        &authority,
        registration.clone(),
        retained.clone(),
    )?;
    let second_check = OverlayReadCheck::capture(
        fixture.layer.commit,
        &authority,
        registration,
        retained.clone(),
    )?;
    let first_reads = source.overlay_node_reads(&selected, &first_check).await?;
    let second_reads = source.overlay_node_reads(&selected, &second_check).await?;
    let first_purpose =
        OverlayPurpose::capture(fixture.layer.commit, &selected, first_scope, first_check)?;
    let second_purpose =
        OverlayPurpose::capture(fixture.layer.commit, &selected, second_scope, second_check)?;
    let first_guard = guard
        .current_history_guard(OverlayHistoryStore::new(&source, &first_reads)?, TokioClock)?;
    let second_guard = guard.current_history_guard(
        OverlayHistoryStore::new(&source, &second_reads)?,
        TokioClock,
    )?;
    let first_pending = first_guard
        .prepare_overlay_history_with_reads(
            fixture.layer.commit,
            first_scope,
            &first_purpose,
            &first_reads,
        )
        .await?;
    let second_pending = second_guard
        .prepare_overlay_history_with_reads(
            fixture.layer.commit,
            second_scope,
            &second_purpose,
            &second_reads,
        )
        .await?;
    assert!(
        first_purpose
            .check(fixture.current.commit, first_scope)
            .is_err()
    );
    assert!(
        CheckedOverlayHistoryInputs::close(
            &fixture.fs,
            &selected,
            &second_purpose,
            &first_reads,
            std::slice::from_ref(&retained),
            std::slice::from_ref(&guard_record),
        )
        .await
        .is_err()
    );
    assert!(
        first
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    assert!(
        second
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );

    // A foreign failed close cannot consume or complete either real invocation.
    // Each original scope still needs its own actual native closing projection.
    let first_closed = CheckedOverlayHistoryInputs::close(
        &fixture.fs,
        &selected,
        &first_purpose,
        &first_reads,
        std::slice::from_ref(&retained),
        std::slice::from_ref(&guard_record),
    )
    .await?;
    let first_history = first_guard.promote_overlay_history(first_pending, first_closed)?;
    assert_eq!(first_history.commits().count(), 2);
    let second_closed = CheckedOverlayHistoryInputs::close(
        &fixture.fs,
        &selected,
        &second_purpose,
        &second_reads,
        std::slice::from_ref(&retained),
        std::slice::from_ref(&guard_record),
    )
    .await?;
    let second_history = second_guard.promote_overlay_history(second_pending, second_closed)?;
    assert_eq!(second_history.commits().count(), 2);
    for resolver in [&first, &second] {
        assert_eq!(
            resolver.observed_completed_view_contexts_for_tests()?.len(),
            2
        );
    }
    assert_eq!(
        guard.store().ref_get(REFERENCE).await?,
        Some(fixture.current.clone())
    );
    Ok(())
}
