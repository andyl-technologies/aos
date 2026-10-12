//! Exercises read-only diagnostics, canonical recovery and actual native final checks.

#[allow(dead_code)]
#[path = "fixture.rs"]
mod fixture;
#[path = "tests/support.rs"]
mod support;

use crate::store::{ContentStore, LocalFs, RefStore};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::refs::Commit;

use super::IndexVerificationStatus;
use fixture::{REFERENCE, TestResult};
use support::*;

const ATTRIBUTE: &str = "hash.sha256";

#[tokio::test]
async fn native_index_verify_reports_divergence_without_mutation() -> TestResult {
    let fixture = complete_population().await?;
    let (repository, selected) = divergent(&fixture).await?;
    let guard = repository.coordinator().guard();
    trace("verify-capture-nonmutation");
    let before = physical(guard.store().root()).await?;
    let original = physical(&fixture.control).await?;
    let publication = publication_image(&repository).await?;
    trace("verify-native-operation");
    let report = guard
        .verify_index(
            REFERENCE,
            &crate::ref_advance::tests::token(),
            "sdk",
            ATTRIBUTE,
        )
        .await?;
    trace("verify-native-complete");
    assert!(
        report
            .indexes
            .iter()
            .any(|index| matches!(index.status, IndexVerificationStatus::Divergent { .. }))
    );
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(selected));
    assert_eq!(physical(guard.store().root()).await?, before);
    assert_eq!(physical(&fixture.control).await?, original);
    assert_eq!(publication_image(&repository).await?, publication);
    let unsupported = guard
        .verify_index(
            REFERENCE,
            &crate::ref_advance::tests::token(),
            "sdk",
            "unregistered.attribute",
        )
        .await;
    assert!(
        matches!(unsupported, Err(super::IndexLookupError::Store(ref error)) if matches!(error.kind(), crate::store::StoreErrorKind::Unsupported))
    );
    assert_eq!(publication_image(&repository).await?, publication);
    Ok(())
}

#[tokio::test]
async fn native_index_rebuild_recovers_divergent_and_missing_auxiliary_closures() -> TestResult {
    let fixture = complete_population().await?;
    let (repository, broken) = divergent(&fixture).await?;
    let token = crate::ref_advance::tests::token();
    assert!(
        repository
            .requalify_fork_source(REFERENCE, &token, "sdk")
            .await
            .is_err()
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(broken.clone())
    );
    let (mut session, request) = repair_request(&repository).await?;
    let rebuilt = repository
        .rebuild_index(&mut session, request, ATTRIBUTE)
        .await?;
    trace("happy-repair-acknowledged");
    let published = rebuilt.record.ok_or("acknowledged rebuild")?;
    assert_ne!(published.commit, broken.commit);
    assert!(
        rebuilt
            .verification
            .indexes
            .iter()
            .any(|index| matches!(index.status, IndexVerificationStatus::Divergent { .. }))
    );
    let token = crate::ref_advance::tests::token();
    let guard = repository.coordinator().guard();
    let verified = guard
        .verify_index(REFERENCE, &token, "sdk", ATTRIBUTE)
        .await?;
    assert!(verified.current.attribute_origin_checks > 0);
    assert!(verified.current.producer_checks > 0);
    assert!(verified.current.producer_entries > 0);
    assert!(
        verified
            .indexes
            .iter()
            .all(|index| matches!(index.status, IndexVerificationStatus::Verified))
    );
    guard.read_snapshot(REFERENCE, &token, b"/", "sdk").await?;
    assert!(
        guard
            .read_commit_snapshot(broken.commit, &token, b"/", "sdk")
            .await
            .is_err()
    );
    // Recreate the native factory and independently install the literal fixture
    // profiles after the repaired head has actually been acknowledged.
    let reopened = reopen(&fixture, guard, &[]).await?;
    assert_eq!(
        reopened.coordinator().store().ref_get(REFERENCE).await?,
        Some(published.clone())
    );
    reopened
        .coordinator()
        .guard()
        .read_snapshot(REFERENCE, &token, b"/", "sdk")
        .await?;

    trace("happy-fresh-reopen-read-complete");
    let mut fork_request = crate::ref_advance::tests::request(Vec::new());
    fork_request.uploads.clear();
    repository
        .fork(REFERENCE, "refs/heads/_/repaired", fork_request)
        .await?;

    trace("happy-repaired-source-fork-complete");
    let mut ordinary = reopened.begin(REFERENCE, &token, "sdk").await?;
    let previous = ordinary.record().ok_or("ordinary source")?;
    let source_identity = TERRANE_V1.from_digest(IdentityKind::Commit, &previous.commit)?;
    let source_bytes = reopened
        .coordinator()
        .store()
        .get(&source_identity, None)
        .await?;
    let source_commit = Commit::decode(&source_bytes)?;
    let mut next_request = crate::ref_advance::tests::request(vec![previous.commit]);
    next_request.commit.tree = source_commit.tree;
    next_request.uploads.clear();
    let advanced = reopened
        .commit_request_with_report(&mut ordinary, next_request)
        .await?;
    assert_ne!(advanced.record.commit, published.commit);
    reopened
        .coordinator()
        .guard()
        .read_snapshot(REFERENCE, &token, b"/", "sdk")
        .await?;

    trace("happy-ordinary-advance-read-complete");
    let missing = complete_population().await?;
    let source = lose_auxiliary(&missing, Loss::Primary).await?;
    let diagnosis = missing
        .repository
        .coordinator()
        .guard()
        .verify_index(REFERENCE, &token, "sdk", ATTRIBUTE)
        .await?;
    assert!(
        diagnosis
            .indexes
            .iter()
            .any(|index| matches!(index.status, IndexVerificationStatus::Incomplete(_)))
    );
    let (mut session, request) = repair_request(&missing.repository).await?;
    let recovered = missing
        .repository
        .rebuild_index(&mut session, request, ATTRIBUTE)
        .await?;
    assert_ne!(
        recovered.record.ok_or("recovery ACK")?.commit,
        source.commit
    );
    // The lost selected placement forces reconstruction on both sides of the
    // raw replacement boundary. The report must charge both real rounds.
    assert!(recovered.namespace_loading.gets > recovered.verification.namespace_loading.gets);
    assert!(recovered.preparation.len() > recovered.verification.indexes.len());
    assert!(recovered.rebuilding.len() > recovered.verification.indexes.len());
    let checked = missing
        .repository
        .coordinator()
        .guard()
        .verify_index(REFERENCE, &token, "sdk", ATTRIBUTE)
        .await?;
    assert!(
        checked
            .indexes
            .iter()
            .all(|index| matches!(index.status, IndexVerificationStatus::Verified))
    );
    missing
        .repository
        .coordinator()
        .guard()
        .read_snapshot(REFERENCE, &token, b"/", "sdk")
        .await?;
    for role in [Loss::PresentRoute, Loss::Gap, Loss::MissingRoute] {
        let missing = partial_index_population().await?;
        lose_auxiliary(&missing, role).await?;
        let before = missing
            .repository
            .coordinator()
            .guard()
            .verify_index(REFERENCE, &token, "sdk", ATTRIBUTE)
            .await?;
        assert!(
            before
                .indexes
                .iter()
                .any(|index| matches!(index.status, IndexVerificationStatus::Incomplete(_)))
        );
        let (mut session, request) = repair_request(&missing.repository).await?;
        missing
            .repository
            .rebuild_index(&mut session, request, ATTRIBUTE)
            .await?;
        let after = missing
            .repository
            .coordinator()
            .guard()
            .verify_index(REFERENCE, &token, "sdk", ATTRIBUTE)
            .await?;
        assert!(
            after
                .indexes
                .iter()
                .all(|index| matches!(index.status, IndexVerificationStatus::Verified))
        );
        assert!(
            after
                .indexes
                .iter()
                .any(|index| !index.missing_values.is_empty())
        );
    }

    // Physical loss permits reconstruction; present unauthentic bytes do not.
    let corrupt = complete().await?;
    let selected = lose_auxiliary(&corrupt, Loss::CorruptPrimary).await?;
    let guard = corrupt.repository.coordinator().guard();
    let diagnosis = guard
        .verify_index(REFERENCE, &token, "sdk", ATTRIBUTE)
        .await;
    assert!(match diagnosis {
        Err(super::IndexLookupError::Index(error)) => {
            error.kind() == crate::indexing::ErrorKind::Invalid
        }
        Err(super::IndexLookupError::Store(error)) => {
            matches!(error.kind(), crate::store::StoreErrorKind::Corrupt(_))
        }
        _ => false,
    });

    let (mut session, request) = repair_request(&corrupt.repository).await?;
    assert!(
        corrupt
            .repository
            .rebuild_index(&mut session, request, ATTRIBUTE)
            .await
            .is_err()
    );
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(selected));
    Ok(())
}

#[tokio::test]
async fn native_index_rebuild_rechecks_original_current_producer_and_final_ack() -> TestResult {
    use std::sync::atomic::Ordering;

    use std::os::unix::fs::PermissionsExt;

    let denied_producer = complete().await?;
    let (repository, selected) = divergent_with_producer(&denied_producer, true).await?;
    let token = crate::ref_advance::tests::token();
    let purpose = super::Purpose {
        source: selected.commit,
    };
    let observation = crate::guard::HistoryObservation::default().maintenance(&purpose);
    let guard = repository.coordinator().guard();
    trace("rechecks-maintenance-source-read");
    let source = guard
        .read_commit_snapshot_observed(selected.commit, &token, b"/", "sdk", observation)
        .await?;
    trace("rechecks-maintenance-source-read-complete");
    trace("rechecks-source-occurrences");
    let occurrences = source.evidence.occurrences(262144)?;
    trace("rechecks-source-occurrences-complete");
    for occurrence in occurrences {
        trace("rechecks-occurrence-tree");
        let tree = source.evidence.tree(occurrence.root, 262144)?;
        trace("rechecks-occurrence-tree-complete");
        let paths = tree
            .iter()
            .filter(|item| {
                matches!(
                    item.entry.kind,
                    terrane_core::tree_format::EntryKind::File { .. }
                )
            })
            .map(|item| {
                let mut path = b"/".to_vec();
                path.extend_from_slice(&item.key);
                path
            })
            .collect::<Vec<_>>();
        for path in paths {
            trace("rechecks-snapshot-authorization");
            guard
                .snapshot_authorizations_observed(&source, &path, observation)
                .await?;
            trace("rechecks-snapshot-authorized");
        }
    }
    trace("rechecks-repair-request");
    let (mut session, request) = repair_request(&repository).await?;
    trace("rechecks-repair-request-complete");
    assert!(
        repository
            .rebuild_index(&mut session, request, ATTRIBUTE)
            .await
            .is_err()
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(selected)
    );

    for kind in [
        Late::SourceOriginal,
        Late::ProducerOriginal,
        Late::CurrentSelection,
    ] {
        late_refusal(kind).await?;
    }

    let unsafe_original = complete().await?;
    let (repository, selected) = divergent(&unsafe_original).await?;
    let (mut session, request) = repair_request(&repository).await?;
    unsafe_original
        .fs
        .set_permissions_and_sync(
            &unsafe_original.control,
            std::fs::Permissions::from_mode(0o777),
        )
        .await?;
    let result = repository
        .rebuild_index(&mut session, request, ATTRIBUTE)
        .await;
    unsafe_original
        .fs
        .set_permissions_and_sync(
            &unsafe_original.control,
            std::fs::Permissions::from_mode(0o700),
        )
        .await?;
    assert!(result.is_err());
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(selected)
    );

    let revoked = complete().await?;
    let (repository, selected) = divergent(&revoked).await?;
    let (mut session, mut request) = repair_request(&repository).await?;
    request.token = b"invalid-current-token".to_vec();
    assert!(
        repository
            .rebuild_index(&mut session, request, ATTRIBUTE)
            .await
            .is_err()
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(selected)
    );

    let fixture = complete().await?;
    let (repository, before) = divergent(&fixture).await?;
    let (mut session, request) = repair_request(&repository).await?;
    let counter = repository
        .coordinator()
        .guard()
        .store()
        .observe_metadata_for_tests()?;
    counter.reset();
    fixture.fs.swallow_ack.store(true, Ordering::SeqCst);
    let result = repository
        .rebuild_index(&mut session, request, ATTRIBUTE)
        .await;
    fixture.fs.swallow_ack.store(false, Ordering::SeqCst);
    assert!(result.is_err());
    assert!(counter.snapshot().commit_puts > 0);
    assert!(fixture.fs.ack_hits.load(Ordering::SeqCst) > 0);
    assert_ne!(
        result
            .as_ref()
            .ok()
            .and_then(|report| report.record.as_ref()),
        Some(&before)
    );
    Ok(())
}

#[tokio::test]
async fn native_index_recovery_refuses_authority_changed_after_durable_replacement() -> TestResult {
    for kind in [
        Late::SourceOriginal,
        Late::ProducerOriginal,
        Late::CurrentSelection,
    ] {
        recovery_boundary_refusal(Some(kind)).await?;
    }
    Ok(())
}

#[tokio::test]
async fn native_index_recovery_preserves_original_deadline_across_replacement() -> TestResult {
    recovery_boundary_refusal(None).await
}

#[tokio::test]
async fn native_index_recovery_refuses_stale_whole_ref_after_actual_repair() -> TestResult {
    let fixture = complete_population().await?;
    let source = lose_auxiliary(&fixture, Loss::Primary).await?;
    let (mut stale, stale_request) = repair_request(&fixture.repository).await?;
    let (mut current, current_request) = repair_request(&fixture.repository).await?;

    // A genuine competing recovery publishes through the ordinary signed-owner
    // path. The earlier session cannot adopt its new whole ref or qualification.
    let repaired = fixture
        .repository
        .rebuild_index(&mut current, current_request, ATTRIBUTE)
        .await?
        .record
        .ok_or("competing repair ACK")?;
    assert_ne!(repaired.commit, source.commit);
    let before = publication_image(&fixture.repository).await?;
    let result = fixture
        .repository
        .rebuild_index(&mut stale, stale_request, ATTRIBUTE)
        .await;

    assert!(result.is_err());
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await?,
        Some(repaired)
    );
    assert_eq!(publication_image(&fixture.repository).await?, before);
    Ok(())
}
