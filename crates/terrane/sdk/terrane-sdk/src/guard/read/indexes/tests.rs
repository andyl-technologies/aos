//! Exercises actual native index answers, incomplete coverage and current retention.

mod current;
mod support;

use std::sync::atomic::Ordering;

use crate::guard::HistoryObservation;
use crate::indexing;
use crate::store::{LocalFs, RefStore, TokioLocalFs};
use terrane_format::derived::AttributeValue;

use super::{IndexLookupError, IndexLookupGap, IndexLookupMethod};
use support::{ATTRIBUTE, Fixture, REFERENCE, TestResult, object, publish, snapshot, value};

#[tokio::test]
async fn native_index_lookup_matches_sha256_and_deduplicates_authorized_occurrences() -> TestResult
{
    let fixture = Fixture::new().await?;
    let report = publish(&fixture.repository, &[b"a", b"b"], &[], true, true).await?;
    let guard = fixture.repository.coordinator().guard();
    let selected = snapshot(&fixture.repository).await?;
    let (_, profile) =
        guard.selected_view_profile(&selected.commit, HistoryObservation::default())?;
    assert_eq!(
        (profile.property_revision, profile.attribute_revision),
        (3, 2)
    );
    assert_eq!(selected.commit.identity(), report.record.commit);
    let before = fixture.fs.effects.load(Ordering::SeqCst);
    let result = guard.lookup_index(&selected, ATTRIBUTE, &value()?).await?;
    assert_eq!(result.objects, vec![object()?]);
    assert_eq!(result.method, IndexLookupMethod::Index);
    assert!(result.is_complete());
    assert_eq!(result.work.candidates.candidates, 1);
    assert_eq!(result.work.present_routes.len(), 1);
    assert_eq!(result.work.present_routes[0].occurrences, 2);
    assert_eq!(result.work.current.occurrence_checks, 2);
    assert_eq!(result.work.current.attribute_origin_checks, 2);
    assert_eq!(fixture.fs.effects.load(Ordering::SeqCst), before);
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(report.record));

    let reopened = fixture.reopen().await?;
    let selected = snapshot(&reopened).await?;
    assert_eq!(
        reopened
            .coordinator()
            .guard()
            .lookup_index(&selected, ATTRIBUTE, &value()?)
            .await?
            .objects,
        vec![object()?]
    );
    Ok(())
}

#[tokio::test]
async fn native_index_lookup_filters_current_acl_trust_and_producer_context() -> TestResult {
    current::current_contexts().await
}

#[tokio::test]
async fn native_index_lookup_reports_gaps_even_when_candidate_range_is_empty() -> TestResult {
    let fixture = Fixture::new().await?;
    // DRV27 backfill: the missing file is already selected before requirements change.
    publish(
        &fixture.repository,
        &[b"present"],
        &[b"missing"],
        false,
        false,
    )
    .await?;
    let head = publish(
        &fixture.repository,
        &[b"present"],
        &[b"missing"],
        true,
        true,
    )
    .await?;
    let selected = snapshot(&fixture.repository).await?;
    let value = AttributeValue::Sha256([0; 32]).encode()?;
    let result = fixture
        .repository
        .coordinator()
        .guard()
        .lookup_index(&selected, ATTRIBUTE, &value)
        .await?;
    assert!(result.objects.is_empty());
    assert_eq!(result.work.candidates.candidates, 0);
    assert_eq!(result.work.gaps.missing_rows, 1);
    assert_eq!(result.work.missing_routes.len(), 1);
    assert_eq!(result.work.missing_routes[0].occurrences, 1);
    assert!(result.work.missing_routes[0].terminal_value_checks > 0);
    assert_eq!(
        result.gaps,
        vec![IndexLookupGap::MissingValue {
            path: b"/missing".to_vec()
        }]
    );
    assert!(!result.is_complete());
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await?,
        Some(head.record)
    );
    Ok(())
}

#[tokio::test]
async fn native_index_lookup_selects_fallback_only_without_owner_binding() -> TestResult {
    let fixture = Fixture::new().await?;
    let head = publish(&fixture.repository, &[b"file"], &[], true, false).await?;
    let selected = snapshot(&fixture.repository).await?;
    let guard = fixture.repository.coordinator().guard();
    match guard.lookup_index(&selected, ATTRIBUTE, &value()?).await {
        Err(IndexLookupError::Index(indexing::Error::MissingBinding(owner))) => {
            assert_eq!(owner, selected.evidence.root)
        }
        Err(other) => panic!("expected genuine missing binding, got {other:?}"),
        Ok(_) => panic!("missing binding supplied apparently complete coverage"),
    }
    let result = guard
        .lookup_index_or_walk(&selected, ATTRIBUTE, &value()?)
        .await?;
    assert_eq!(result.objects, vec![object()?]);
    assert_eq!(result.method, IndexLookupMethod::Walk);
    assert_eq!(result.gaps, vec![IndexLookupGap::MissingBinding]);
    assert!(!result.is_complete());
    assert!(result.work.preparation.is_none());
    assert_eq!(result.work.walked_files, 1);
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(head.record));
    current::bound_failure_never_walks().await?;
    Ok(())
}

#[tokio::test]
async fn native_index_lookup_rechecks_held_current_controls_before_return() -> TestResult {
    let fixture = Fixture::new().await?;
    let head = publish(&fixture.repository, &[b"file"], &[], true, true).await?;
    let selected = snapshot(&fixture.repository).await?;
    let guard = fixture.repository.coordinator().guard();
    let canonical = value()?;
    fixture.fs.clear_trace();
    guard.lookup_index(&selected, ATTRIBUTE, &canonical).await?;
    let path = fixture.control.join("registration.cbor");
    let reads = fixture
        .fs
        .trace()
        .iter()
        .filter(|read| *read == &path)
        .count();
    assert!(
        reads > 1,
        "no actual final Original registration read observed"
    );
    fixture.fs.clear_trace();
    let handoff = fixture.fs.pause(path.clone(), reads);
    let mut lookup = Box::pin(guard.lookup_index(&selected, ATTRIBUTE, &canonical));
    tokio::select! {
        result = &mut lookup => panic!("lookup completed before final Original handoff: {result:?}"),
        signal = handoff.wait() => signal?,
    }
    assert_eq!(handoff.hits.load(Ordering::SeqCst), 1);
    let competing = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.control.join("retention.lock"))?;
    assert!(matches!(
        competing.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    let bytes = TokioLocalFs.read_nofollow(&path).await?;
    let metadata = TokioLocalFs.symlink_metadata(&path).await?;
    let replacement = path.with_extension("replacement");
    TokioLocalFs.write_new(&replacement, &bytes).await?;
    TokioLocalFs
        .set_permissions_and_sync(&replacement, metadata.permissions())
        .await?;
    TokioLocalFs.rename(&replacement, &path).await?;
    TokioLocalFs.sync_directory(&fixture.control).await?;
    handoff.release();
    match lookup.await {
        Err(IndexLookupError::Store(failure)) => {
            assert_eq!(failure.kind(), crate::guard::invalid().kind())
        }
        Err(other) => panic!("expected exact replaced protected input refusal, got {other:?}"),
        Ok(_) => panic!("changed Original incarnation yielded an answer"),
    }
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(head.record));
    current::cancel_without_result().await?;
    Ok(())
}

#[tokio::test]
async fn native_index_lookup_separates_loading_validation_candidates_occurrences_and_current_work()
-> TestResult {
    let fixture = Fixture::new().await?;
    publish(
        &fixture.repository,
        &[b"a", b"b"],
        &[b"missing"],
        false,
        false,
    )
    .await?;
    publish(
        &fixture.repository,
        &[b"a", b"b"],
        &[b"missing"],
        true,
        true,
    )
    .await?;
    let selected = snapshot(&fixture.repository).await?;
    let result = fixture
        .repository
        .coordinator()
        .guard()
        .lookup_index(&selected, ATTRIBUTE, &value()?)
        .await?;
    assert_eq!(result.objects, vec![object()?]);
    assert_eq!(result.work.candidates.candidates, 1);
    assert_eq!(result.work.present_routes[0].occurrences, 2);
    assert_eq!(result.work.gaps.missing_rows, 1);
    assert_eq!(result.work.missing_routes[0].occurrences, 1);
    assert!(result.work.loading.gets > 0);
    assert!(result.work.reconstruction.compared_nodes > 0);
    let prepared = match result.work.preparation.as_ref() {
        Some(prepared) => prepared,
        None => panic!("indexed result lacks actual relationship preparation"),
    };
    assert!(prepared.loaded_nodes > 0);
    assert_eq!(prepared.verification.candidates, 1);
    assert_eq!(prepared.verification.missing_objects, 1);
    assert_eq!(result.work.walked_files, 0);
    assert_eq!(result.work.current.occurrence_checks, 3);
    assert_eq!(result.work.current.attribute_origin_checks, 2);
    assert!(result.work.current.producer_entries >= 4);
    assert!(result.work.current.producer_checks >= 2);
    assert!(result.work.current.history_boundary_calls > 0);
    assert!(result.work.current.token_refreshes > 0);
    assert!(result.work.current.physical_read_checks > 0);
    assert!(result.work.current.control_record_checks > 0);
    assert!(!result.is_complete());
    Ok(())
}
