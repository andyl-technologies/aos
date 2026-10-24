//! Checks finite checkpoint bytes, current refusals and measured native content work.

pub(in crate::guard) mod fixture;

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;

use crate::bucket::held::SingleHeld;
use crate::guard::{TreeEvidence, invalid};
use crate::indexing::{self, SemanticRevisions};
use crate::store::{ContentStore, LocalFs, RefStore, StoreErrorKind};
use terrane_format::auth::Verb;
use terrane_format::derived::{AttributeValue, Magic};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::provenance::{Preset, Selector};
use terrane_format::refs::EntryOrigin;

use super::super::{IndexBackfillGapReason, IndexBackfillReport};
use fixture::{BODY, Fixture, REFERENCE, SHA256, TestResult};

/// Calibrates real successful and absent typed reads through clones and held adapters.
///
/// # Errors
/// Preserves actual exclusion, catalog and body-read failures.
/// # Panics
/// Panics when real typed attempts or same-Arc sharing do not match independently counted reads.
async fn calibrate(fixture: &Fixture) -> TestResult {
    let bucket = fixture.repository.coordinator().guard().store();
    let counter = bucket.observe_metadata_for_tests()?;
    let clone = bucket.clone();
    assert!(std::sync::Arc::ptr_eq(
        &counter,
        &clone.observe_metadata_for_tests()?
    ));
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(BODY);
    counter.reset();
    assert_eq!(clone.get(&identity, None).await?, encoded);
    let absent = TERRANE_V1.calculate(IdentityKind::Chunk, b"not uploaded in this fixture")?;
    let missing_clone = clone.get(&absent, None).await;

    // Ordinary clone reads acquire their own exclusion and must finish before
    // this fixture retains the conflicting exclusive holder.
    let held = SingleHeld::acquire(bucket).await?;
    assert_eq!(held.destination().get(&identity, None).await?, encoded);
    for result in [missing_clone, held.destination().get(&absent, None).await] {
        assert!(
            matches!(result, Err(ref error) if matches!(error.kind(), StoreErrorKind::Absent(actual) if actual == &absent))
        );
    }
    assert_eq!(counter.snapshot().chunk_gets, 4);
    drop(held);
    counter.reset();
    Ok(())
}

/// Exercises exact checked value reuse and authored receipts without forged historical origin.
///
/// # Errors
/// Preserves genuine actual producer history, current and publication failures.
/// # Panics
/// Panics for wrong immutable bytes, physical attempt counts or signed receipts.
pub(super) async fn reuse() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.publish(false).await?;
    let (record, bytes) = fixture
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    fixture.policy(&["hash.sha256"], None, None).await?;
    calibrate(&fixture).await?;
    let (mut session, request) = fixture.template().await?;
    let counter = fixture
        .repository
        .coordinator()
        .guard()
        .store()
        .observe_metadata_for_tests()?;
    counter.reset();
    let report = fixture
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    assert!(report.is_complete());
    assert_eq!(report.copied.len(), 1);
    assert_eq!(report.copied[0].record, record);
    assert_eq!(report.copied[0].producer, first.commit);
    assert_eq!(
        report.copied[0].value,
        AttributeValue::Sha256(SHA256).encode()?
    );
    assert_eq!(report.copied[0].paths, vec![b"/file".to_vec()]);
    assert_eq!(counter.snapshot().chunk_gets, 0);
    assert!(counter.snapshot().node_gets > 0);
    assert!(counter.snapshot().node_puts > 0);
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .guard()
            .store()
            .get(&record, None)
            .await?,
        bytes
    );
    let committed = report.record.ok_or_else(invalid)?;
    let guard = fixture.repository.coordinator().guard();
    let history = guard.verified_history(committed.commit).await?;
    let commit = history.commit(&committed.commit).ok_or_else(invalid)?;
    let receipt = commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_ref()
        .ok_or_else(invalid)?
        .iter()
        .find(|receipt| receipt.path == b"file")
        .ok_or_else(invalid)?;
    let attributes = receipt.attributes.as_ref().ok_or_else(invalid)?;
    assert!(
        attributes
            .iter()
            .any(|(name, origin)| name == "hash.sha256" && matches!(origin, EntryOrigin::Current))
    );

    let (mut session, request) = fixture.template().await?;
    let unchanged = fixture
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    assert!(unchanged.copied.is_empty());
    assert!(unchanged.record.is_none());
    assert!(unchanged.is_complete());
    Ok(())
}

/// Exercises invalid signatures, absent evidence, atomic deferral and conditional unknowns.
///
/// # Errors
/// Preserves real setup, selected storage and normal publication failures.
/// # Panics
/// Panics when unqualified evidence counts as complete or a partial file is changed.
pub(super) async fn gaps() -> TestResult {
    for invalid_signature in [false, true] {
        let fixture = Fixture::new().await?;
        let first = fixture.publish(false).await?;
        if invalid_signature {
            fixture
                .side(first.commit, AttributeValue::Sha256(SHA256), false)
                .await?;
        }
        fixture.policy(&["hash.sha256"], None, None).await?;
        let (mut session, request) = fixture.template().await?;
        let report = fixture
            .repository
            .backfill_index_inputs(&mut session, request)
            .await?;
        assert!(!report.is_complete());
        assert!(report.copied.is_empty());
        assert!(
            report
                .gaps
                .iter()
                .any(|gap| gap.attribute == "hash.sha256" && gap.path == b"/file")
        );
        let root = session.record().ok_or_else(invalid)?.commit;
        let evidence = TreeEvidence::load_commit(
            fixture.repository.coordinator().guard().store(),
            root,
            262144,
        )
        .await?;
        let tree = evidence.tree(evidence.root, 262144)?;
        assert!(
            tree.get(b"file")
                .ok_or_else(invalid)?
                .attrs
                .iter()
                .all(|attribute| attribute.name != "hash.sha256")
        );
    }
    for unavailable in [false, true] {
        let fixture = Fixture::new().await?;
        let first = fixture.publish(false).await?;
        fixture.side_variant(first.commit, unavailable).await?;
        fixture.policy(&["hash.sha256"], None, None).await?;
        let (mut session, request) = fixture.template().await?;
        let report = fixture
            .repository
            .backfill_index_inputs(&mut session, request)
            .await?;
        assert!(report.copied.is_empty());
        assert!(!report.is_complete());
        assert!(!report.gaps.is_empty());
        if unavailable {
            assert!(
                report
                    .gaps
                    .iter()
                    .any(|gap| gap.reason == IndexBackfillGapReason::UnavailableEvidence)
            );
        }
    }

    let fixture = Fixture::new().await?;
    let first = fixture.publish(false).await?;
    fixture
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    fixture
        .policy(&["class.elf", "hash.sha256"], None, None)
        .await?;
    let (mut session, request) = fixture.template().await?;
    let report = fixture
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    assert!(report.copied.is_empty());
    assert!(!report.is_complete());
    assert!(report.gaps.iter().any(|gap| gap.attribute == "class.elf"
        && gap.reason == IndexBackfillGapReason::UnknownApplicability));
    assert!(
        report.gaps.iter().any(|gap| gap.attribute == "hash.sha256"
            && gap.reason == IndexBackfillGapReason::DeferredFile)
    );

    // A genuinely signed same-version contradiction must not pick a convenient
    // first record or overwrite an existing agreeing inline value.
    let conflict = Fixture::new().await?;
    let first = conflict.publish(false).await?;
    conflict
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    conflict
        .side(first.commit, AttributeValue::Sha256([7; 32]), true)
        .await?;
    conflict.policy(&["hash.sha256"], None, None).await?;
    let (mut session, request) = conflict.template().await?;
    let report = conflict
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    assert!(report.copied.is_empty());
    assert!(
        report
            .gaps
            .iter()
            .any(|gap| gap.reason == IndexBackfillGapReason::ValueDisagreement)
    );
    Ok(())
}

/// Refuses genuine current/Original changes and an executor that omits the real final receipt.
///
/// # Errors
/// Preserves actual fixture setup and signed transition failures.
/// # Panics
/// Panics when mandatory input failures succeed or missing acknowledgment never executes.
pub(super) async fn current() -> TestResult {
    let denied = Fixture::new().await?;
    let first = denied.publish(false).await?;
    denied
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    denied
        .policy(&["hash.sha256"], Some(Verb::Read as u64), None)
        .await?;
    match denied.template().await {
        Err(error) => {
            assert!(
                matches!(error.downcast_ref::<crate::repository::Error>(), Some(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(failure))) if matches!(failure.kind(), StoreErrorKind::Denied { .. }))
            );
        }
        Ok((mut session, request)) => {
            let result = denied
                .repository
                .backfill_index_inputs(&mut session, request)
                .await;
            assert!(
                matches!(result, Err(crate::repository::Error::Store(ref failure)) if matches!(failure.kind(), StoreErrorKind::Denied { .. }))
            );
        }
    }

    let original = Fixture::new().await?;
    let first = original.publish(false).await?;
    original
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    original.policy(&["hash.sha256"], None, None).await?;
    let (mut session, request) = original.template().await?;
    let before = original
        .repository
        .coordinator()
        .guard()
        .store()
        .ref_get(REFERENCE)
        .await?;
    original
        .fs
        .set_permissions_and_sync(&original.control, std::fs::Permissions::from_mode(0o777))
        .await?;
    let result = original
        .repository
        .backfill_index_inputs(&mut session, request)
        .await;
    original
        .fs
        .set_permissions_and_sync(&original.control, std::fs::Permissions::from_mode(0o700))
        .await?;
    assert!(result.is_err());
    assert_eq!(
        original
            .repository
            .coordinator()
            .guard()
            .store()
            .ref_get(REFERENCE)
            .await?,
        before
    );

    let trust = Fixture::new().await?;
    let first = trust.publish(false).await?;
    trust
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    let installed = trust
        .policy(
            &["hash.sha256"],
            None,
            Some(Selector::preset(Preset::Attested).encode().to_vec()),
        )
        .await?;
    let (mut session, request) = trust.template().await?;
    let bucket = trust.repository.coordinator().guard().store();
    let before = bucket.ref_get(REFERENCE).await?;
    assert_eq!(before, Some(installed.record.clone()));
    let view = TERRANE_V1.from_digest(IdentityKind::Commit, &installed.record.commit)?;
    let counter = bucket.observe_metadata_for_tests()?;
    counter.reset();

    // Missing bindings still require a genuine source-owner publication. The
    // Attested selector hides this unattested source occurrence as absent.
    let result = trust
        .repository
        .backfill_index_inputs(&mut session, request)
        .await;
    assert!(
        matches!(result, Err(crate::repository::Error::Store(ref failure)) if matches!(failure.kind(), StoreErrorKind::Absent(actual) if actual == &view))
    );
    assert_eq!(counter.snapshot().chunk_gets, 0);
    assert_eq!(bucket.ref_get(REFERENCE).await?, before);
    let bytes = bucket.get(&view, None).await?;
    TERRANE_V1.verify(&view, &bytes)?;

    let missing_ack = Fixture::new().await?;
    let first = missing_ack.publish(false).await?;
    missing_ack
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    missing_ack.policy(&["hash.sha256"], None, None).await?;
    let (mut session, request) = missing_ack.template().await?;
    let counter = missing_ack
        .repository
        .coordinator()
        .guard()
        .store()
        .observe_metadata_for_tests()?;
    counter.reset();
    missing_ack.fs.swallow_ack.store(true, Ordering::SeqCst);
    let result = missing_ack
        .repository
        .backfill_index_inputs(&mut session, request)
        .await;
    missing_ack.fs.swallow_ack.store(false, Ordering::SeqCst);
    // A candidate Commit must actually be uploaded before this selected-tail
    // failure; an earlier retention/setup acknowledgment is not this witness.
    assert!(counter.snapshot().commit_puts > 0);
    assert!(missing_ack.fs.ack_hits.load(Ordering::SeqCst) > 0);
    assert!(result.is_err());
    Ok(())
}

/// Reports bounded fixture phases without enabling per-record native diagnostics.
///
/// # Panics
/// Panics if enabled diagnostics cannot write to standard error.
fn mark_complete_phase(trace: &crate::ref_advance::NativeTrace, phase: &'static str) {
    trace.mark(phase);
    if std::env::var_os("TERRANE_BACKFILL_PHASE_TRACE").is_some() {
        eprintln!("backfill-phase phase={phase}");
    }
}

/// Creates one genuine repeated-graft backfill history for a single owning case.
///
/// # Errors
/// Preserves actual producer, current policy, checkpoint and side-record failures.
/// # Panics
/// Panics when materialization, coverage or content-read assertions fail.
async fn complete_fixture(
    trace: &crate::ref_advance::NativeTrace,
) -> TestResult<(Fixture, IndexBackfillReport)> {
    mark_complete_phase(trace, "fixture-initialization-entry");
    let fixture = Fixture::new().await?;
    mark_complete_phase(trace, "fixture-initialization-returned");
    mark_complete_phase(trace, "fixture-first-publication-entry");
    let first = fixture.publish(true).await?;
    mark_complete_phase(trace, "fixture-first-publication-complete");
    fixture
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    fixture
        .side(first.commit, AttributeValue::Magic(Magic::Text), true)
        .await?;
    mark_complete_phase(trace, "fixture-side-record-publications-returned");
    let counter = fixture
        .repository
        .coordinator()
        .guard()
        .store()
        .observe_metadata_for_tests()?;
    counter.reset();
    mark_complete_phase(trace, "fixture-policy-publication-entry");
    let installed = fixture
        .policy(&["class.elf", "hash.sha256"], None, None)
        .await?;
    assert_eq!(counter.snapshot().chunk_gets, 0);
    assert!(!installed.index_work.gaps.is_empty());
    mark_complete_phase(trace, "fixture-policy-publication-complete-template-entry");
    let (mut session, request) = fixture.template().await?;
    mark_complete_phase(trace, "actual-session-request-captured");
    counter.reset();
    mark_complete_phase(trace, "backfill-entry");
    let report = fixture
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    mark_complete_phase(trace, "backfill-returned");
    assert!(report.is_complete());
    assert_eq!(counter.snapshot().chunk_gets, 0);
    assert_eq!(report.coverage.file_occurrences, 3);
    assert_eq!(report.coverage.raw_missing_index_inputs, 6);
    assert!(report.coverage.materialized_inputs >= 6);
    assert_eq!(report.initialization.len(), 4);
    assert!(
        report
            .initialization
            .iter()
            .all(|work| work.construction.kind
                == terrane_format::indexing::maintenance::ConstructionKind::NewlyEnabled)
    );
    Ok((fixture, report))
}

/// Materializes repeated-graft inputs and verifies carriers and warm current lookup.
///
/// # Errors
/// Preserves producer, signed checkpoint, auxiliary loading and current lookup failures.
/// # Panics
/// Panics for wrong applicability, construction mode, winning bytes or deduplicated lookup.
pub(super) async fn complete() -> TestResult {
    let trace = crate::ref_advance::NativeTrace::new(
        std::path::Path::new("<completeness-fixture>"),
        "fourth-selector",
    );
    let (fixture, report) = complete_fixture(&trace).await?;
    let committed = report.record.as_ref().ok_or_else(invalid)?;
    let guard = fixture.repository.coordinator().guard();
    mark_complete_phase(&trace, "winning-snapshot-entry");
    let snapshot = guard
        .read_snapshot(REFERENCE, &crate::ref_advance::tests::token(), b"/", "sdk")
        .await?;
    assert_eq!(snapshot.commit.identity(), committed.commit);
    mark_complete_phase(&trace, "winning-snapshot-returned-sha-index-load-entry");
    let loaded = indexing::load(
        guard.store(),
        snapshot.evidence.root,
        "hash.sha256",
        SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
    )
    .await?;
    mark_complete_phase(&trace, "sha-index-load-returned");
    {
        let sources = loaded.sources()?;
        let prepared = loaded.prepare(&sources.trees)?;
        let value = AttributeValue::Sha256(SHA256).encode()?;
        let candidates = prepared.candidates(&value)?;
        assert_eq!(candidates.rows.len(), 1);
    }
    mark_complete_phase(&trace, "sha-index-validation-returned-elf-index-load-entry");

    // Positive Text evidence closes applicability, not the raw missing-value
    // relationship: all three actual ELF absences must remain in G.
    let elf = indexing::load(
        guard.store(),
        snapshot.evidence.root,
        "class.elf",
        SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
    )
    .await?;
    mark_complete_phase(&trace, "elf-index-load-returned");
    {
        let sources = elf.sources()?;
        let prepared = elf.prepare(&sources.trees)?;
        assert!(prepared.gap_root().is_some());
        assert_eq!(prepared.preparation().verification.missing_objects, 1);
        let missing = prepared.all_missing()?;
        assert_eq!(missing.rows.len(), 1);
        let candidate = missing.rows.first().ok_or_else(invalid)?;
        assert!(candidate.value().is_none());
        let occurrences = candidate.occurrences()?;
        assert_eq!(occurrences.rows.len(), 3);

        let mut paths = Vec::new();
        for occurrence in &occurrences.rows {
            assert!(occurrence.value.is_none());
            assert!(
                occurrence
                    .entry
                    .attrs
                    .iter()
                    .all(|attribute| attribute.name != "class.elf")
            );
            let mut path = Vec::new();
            for hop in &occurrence.hops {
                path.push(b'/');
                path.extend_from_slice(&hop.key);
            }
            path.push(b'/');
            path.extend_from_slice(&occurrence.key);
            paths.push(path);
        }
        paths.sort();
        assert_eq!(
            paths,
            vec![b"/a/file".to_vec(), b"/b/file".to_vec(), b"/file".to_vec()]
        );
    }
    assert!(report.is_complete());
    mark_complete_phase(&trace, "elf-index-validation-returned-current-lookup-entry");

    let value = AttributeValue::Sha256(SHA256).encode()?;
    let lookup = guard.lookup_index(&snapshot, "hash.sha256", &value).await?;
    assert!(lookup.is_complete());
    assert_eq!(
        lookup.objects,
        vec![
            TERRANE_V1
                .calculate(IdentityKind::Chunk, BODY)?
                .terrane_v1_digest()?
        ]
    );
    mark_complete_phase(&trace, "current-lookup-returned");
    Ok(())
}

/// Repeats genuine materialization before independently reopening protected carriers.
///
/// # Errors
/// Preserves producer, signed checkpoint, protected factory and current lookup failures.
/// # Panics
/// Panics when the reopened winning commit, complete lookup or object set differs.
pub(super) async fn protected_reopen() -> TestResult {
    let trace = crate::ref_advance::NativeTrace::new(
        std::path::Path::new("<protected-reopen-fixture>"),
        "protected-reopen-selector",
    );
    let (fixture, report) = complete_fixture(&trace).await?;
    let committed = report.record.as_ref().ok_or_else(invalid)?;
    mark_complete_phase(&trace, "protected-reopen-entry");
    let reopened = fixture.reopen().await?;
    mark_complete_phase(&trace, "reopen-returned-snapshot-entry");
    let snapshot = reopened
        .coordinator()
        .guard()
        .read_snapshot(REFERENCE, &crate::ref_advance::tests::token(), b"/", "sdk")
        .await?;
    assert_eq!(snapshot.commit.identity(), committed.commit);
    mark_complete_phase(&trace, "reopened-snapshot-returned-current-lookup-entry");
    let value = AttributeValue::Sha256(SHA256).encode()?;
    let lookup = reopened
        .coordinator()
        .guard()
        .lookup_index(&snapshot, "hash.sha256", &value)
        .await?;
    assert!(lookup.is_complete());
    assert_eq!(
        lookup.objects,
        vec![
            TERRANE_V1
                .calculate(IdentityKind::Chunk, BODY)?
                .terrane_v1_digest()?
        ]
    );
    mark_complete_phase(&trace, "reopened-current-lookup-returned");
    Ok(())
}

/// Publishes a finite incremental backfill for an actual existing required binding.
///
/// # Errors
/// Preserves producer, binding installation, signed checkpoint and current failures.
/// # Panics
/// Panics for unexpected initialization, copied paths or construction mode.
pub(super) async fn existing_binding() -> TestResult {
    let trace = crate::ref_advance::NativeTrace::new(
        std::path::Path::new("<existing-binding-fixture>"),
        "existing-binding-selector",
    );
    mark_complete_phase(&trace, "maintained-fixture-entry");
    let maintained = Fixture::new().await?;
    mark_complete_phase(
        &trace,
        "maintained-fixture-returned-first-publication-entry",
    );
    let producer = maintained.partial().await?;
    mark_complete_phase(
        &trace,
        "maintained-first-publication-returned-side-record-entry",
    );
    maintained
        .side(producer.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    mark_complete_phase(
        &trace,
        "maintained-side-record-returned-bound-requirement-entry",
    );
    maintained.bound_requirement().await?;
    mark_complete_phase(
        &trace,
        "maintained-bound-requirement-returned-template-entry",
    );
    let (mut session, request) = maintained.template().await?;
    mark_complete_phase(&trace, "maintained-template-returned-backfill-entry");
    let report = maintained
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    mark_complete_phase(&trace, "maintained-backfill-returned");
    assert!(report.is_complete());
    assert!(report.initialization.is_empty());
    assert_eq!(report.copied.len(), 1);
    assert_eq!(report.copied[0].paths, vec![b"/other".to_vec()]);
    assert!(report.index_work.operations.iter().any(|operation| {
        operation.initialization.is_none()
            && operation.update.as_ref().is_some_and(|update| {
                update.mode == terrane_format::indexing::incremental::PopulationMode::Existing
            })
    }));
    Ok(())
}
