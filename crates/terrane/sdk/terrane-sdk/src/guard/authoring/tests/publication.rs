//! Proves actual selected index publication, maintenance and incomplete binding semantics.

mod locality;
mod support;

use super::TestResult;
use crate::guard::{HistoryObservation, SelectedReadInterpretation, invalid};
use crate::indexing::{self, SemanticRevisions};
use crate::store::{ContentStore, RefStore, StoreErrorKind, StoreFailure};
use std::collections::BTreeMap;
use std::error::Error as _;
use support::{REFERENCE, expected, publish, repository, request};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Checks real complete auxiliary bytes and independently executed history/context.
///
/// # Errors
/// Preserves genuine native setup, admission, Original and publication failures.
/// # Panics
/// Panics if independently expected bytes, work or selected-state assertions fail.
pub(super) async fn selected_required_index_publishes_real_context_and_full_carriers() -> TestResult
{
    let repository = repository(2).await?;
    let (primary, nodes) = expected(Some(1))?;
    let first = publish(&repository, Some(1), true, Some(primary), &nodes).await?;
    assert_eq!(first.index_work.operations.len(), 1);
    let operation = &first.index_work.operations[0];
    assert!(operation.initialization.is_some());
    assert!(operation.update.is_none());
    assert_eq!(operation.association.index, primary);
    assert_eq!(operation.paths, vec![b"/".to_vec()]);
    let namespace = first.index_work.namespace_inputs.ok_or_else(invalid)?;
    assert!(namespace.retained_calls > 0);
    assert_eq!(namespace.store_calls, 0);
    let supplied = operation.supplied_inputs.ok_or_else(invalid)?;
    assert!(supplied.staged_calls > 0);
    assert_eq!(supplied.store_calls, 0);
    let guard = repository.coordinator().guard();
    for (digest, bytes) in &nodes {
        let id = TERRANE_V1.from_digest(IdentityKind::Node, digest)?;
        assert_eq!(guard.store().get(&id, None).await?, *bytes);
    }
    let history = guard.verified_history(first.record.commit).await?;
    let commit = history.commit(&first.record.commit).ok_or_else(invalid)?;
    assert_eq!(commit.commit().tree, operation.owner);
    let (selected, profile) = guard.selected_view_profile(commit, HistoryObservation::default())?;
    assert!(matches!(selected, SelectedReadInterpretation::Recorded(_)));
    assert_eq!(
        (profile.property_revision, profile.attribute_revision),
        (3, 2)
    );
    let loaded = indexing::load(guard.store(), operation.owner, "uid", revisions(), 262144).await?;
    let sources = loaded.sources()?;
    let prepared = loaded.prepare(&sources.trees)?;
    assert_eq!(prepared.root(), primary);
    assert_eq!(prepared.candidates(&[1])?.rows.len(), 1);

    let second = publish(&repository, Some(2), true, Some(primary), &BTreeMap::new()).await?;
    let operation = &second.index_work.operations[0];
    let (updated, expected_nodes) = expected(Some(2))?;
    assert_eq!(operation.association.index, updated);
    assert!(operation.initialization.is_none());
    let update = operation.update.as_ref().ok_or_else(invalid)?;
    assert_eq!(
        update.mode,
        terrane_format::indexing::incremental::PopulationMode::Existing
    );
    assert_eq!(update.delta_data, 1);
    assert!(update.delta_input >= 1);
    assert!(operation.boundary.is_some());
    assert!(operation.old_index.is_some());
    assert!(operation.old_inputs.ok_or_else(invalid)?.store_calls > 0);
    assert!(operation.old_reconstruction.is_some());
    assert!(operation.old_source.is_some());
    assert!(operation.new_source.nodes > 0);
    assert!(!second.index_work.completion.is_empty());
    for (digest, bytes) in expected_nodes {
        assert_eq!(
            guard
                .store()
                .get(&TERRANE_V1.from_digest(IdentityKind::Node, &digest)?, None)
                .await?,
            bytes
        );
    }
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(second.record));
    Ok(())
}

/// Refuses an independently addressed wrong relationship before immutable writes.
///
/// # Errors
/// Preserves genuine native setup, admission, Original and publication failures.
/// # Panics
/// Panics if independently expected bytes, work or selected-state assertions fail.
pub(super) async fn selected_required_index_refuses_divergence_before_immutable_effects()
-> TestResult {
    let repository = repository(2).await?;
    let (wrong, nodes) = expected(Some(2))?;
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let (tree, request) =
        request(&repository, Vec::new(), Some(1), true, Some(wrong), &nodes).await?;
    let owner = tree.root();
    let result = repository
        .commit_with_report(&mut session, tree, request)
        .await;
    let failure = refused(result);
    assert_eq!(failure.kind(), invalid().kind());
    let source = failure
        .source()
        .and_then(|source| source.downcast_ref::<indexing::Error>())
        .ok_or_else(invalid)?;
    assert_eq!(source.kind(), indexing::ErrorKind::Invalid);
    assert_eq!(source.subject(), Some(owner));
    assert!(
        repository
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await?
            .is_none()
    );
    let id = TERRANE_V1.from_digest(IdentityKind::Node, &owner)?;
    assert_eq!(
        repository.coordinator().store().has(&[id]).await?,
        vec![false]
    );
    Ok(())
}

/// Retains explicitly inert old attributes under the old independently selected profile.
///
/// # Errors
/// Preserves genuine native setup, admission, Original and publication failures.
/// # Panics
/// Panics if independently expected bytes, work or selected-state assertions fail.
pub(super) async fn selected_required_index_preserves_old_inert_historical_profiles() -> TestResult
{
    let repository = repository(1).await?;
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let (tree, mut request) = request(
        &repository,
        Vec::new(),
        Some(1),
        false,
        None,
        &BTreeMap::new(),
    )
    .await?;
    let actual = tree.tree()?;
    let mut entries = actual.iter().cloned().collect::<Vec<_>>();
    let first = entries.first_mut().ok_or_else(invalid)?;
    first
        .entry
        .attrs
        .push(terrane_format::tree_format::Attribute {
            name: "index.occurrences",
            value: b"\x40",
        });
    first
        .entry
        .attrs
        .sort_by(|left, right| left.name.cmp(right.name));
    let rebuilt = terrane_format::tree_builder::Tree::build(
        entries,
        actual.props().map(<[_]>::to_vec),
        262144,
        terrane_format::tree_format::TreeUse::Ordinary,
    )?;
    let prepared = crate::repository::PreparedTree::from_tree(&rebuilt)?;
    request.commit.tree = prepared.root();
    let first = repository
        .commit_with_report(&mut session, prepared, request)
        .await?;
    assert!(first.index_work.namespace_loading.is_none());
    let guard = repository.coordinator().guard();
    let history = guard.verified_history(first.record.commit).await?;
    let commit = history.commit(&first.record.commit).ok_or_else(invalid)?;
    let (_, profile) = guard.selected_view_profile(commit, HistoryObservation::default())?;
    assert_eq!(profile.attribute_revision, 1);
    assert_eq!(profile.property_revision, 3);
    Ok(())
}

/// Preserves truthful absent coverage and refuses omission of a verified maintained binding.
///
/// # Errors
/// Preserves genuine native setup, admission, Original and publication failures.
/// # Panics
/// Panics if independently expected bytes, work or selected-state assertions fail.
pub(super) async fn selected_required_index_distinguishes_preserved_gaps_and_dropped_bindings()
-> TestResult {
    let repository = repository(2).await?;
    let initial = publish(&repository, Some(1), true, None, &BTreeMap::new()).await?;
    assert_eq!(initial.index_work.gaps.len(), 1);
    assert!(initial.index_work.operations.is_empty());
    let preserved = publish(&repository, Some(1), true, None, &BTreeMap::new()).await?;
    assert_eq!(preserved.index_work.gaps.len(), 1);
    assert!(preserved.index_work.operations.is_empty());
    repository
        .coordinator()
        .guard()
        .verified_history(preserved.record.commit)
        .await?;
    let (primary, nodes) = expected(Some(1))?;
    let installed = publish(&repository, Some(1), true, Some(primary), &nodes).await?;
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let (tree, request) = request(
        &repository,
        vec![installed.record.commit],
        Some(1),
        true,
        None,
        &BTreeMap::new(),
    )
    .await?;
    let owner = tree.root();
    let failure = refused(
        repository
            .commit_with_report(&mut session, tree, request)
            .await,
    );
    assert_eq!(failure.kind(), invalid().kind());
    let source = failure
        .source()
        .and_then(|source| {
            source.downcast_ref::<crate::guard::admission::index_writer::DroppedBinding>()
        })
        .ok_or_else(invalid)?;
    assert_eq!(source.owner, owner);
    assert_eq!(source.attribute, "uid");
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(installed.record)
    );
    let missing = support::repository(2).await?;
    let mut empty_session = missing.begin(REFERENCE, &token, "sdk").await?;
    let (tree, request) =
        support::request(&missing, Vec::new(), None, true, None, &BTreeMap::new()).await?;
    let owner = tree.root();
    let failure = refused(
        missing
            .commit_with_report(&mut empty_session, tree, request)
            .await,
    );
    assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
    let source = failure
        .source()
        .and_then(|source| {
            source.downcast_ref::<crate::guard::admission::index_inline::MissingInline>()
        })
        .ok_or_else(invalid)?;
    assert_eq!(
        source.object,
        TERRANE_V1
            .calculate(IdentityKind::Chunk, support::BODY)?
            .terrane_v1_digest()?
    );
    assert_eq!(source.attribute, "uid");
    assert_eq!(
        missing
            .coordinator()
            .store()
            .has(&[TERRANE_V1.from_digest(IdentityKind::Node, &owner)?])
            .await?,
        vec![false]
    );
    assert!(
        missing
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await?
            .is_none()
    );
    // Enabling a requirement on an untouched old entry preserves its genuine
    // missing value. A supplied exact relationship retains G until backfill.
    let backfill = support::repository(2).await?;
    publish(&backfill, None, false, None, &BTreeMap::new()).await?;
    let (gap_index, gap_nodes) = expected(None)?;
    let enabled = publish(&backfill, None, true, Some(gap_index), &gap_nodes).await?;
    let operation = &enabled.index_work.operations[0];
    assert_eq!(operation.association.index, gap_index);
    let loaded = indexing::load(
        backfill.coordinator().store(),
        operation.owner,
        "uid",
        revisions(),
        262144,
    )
    .await?;
    let sources = loaded.sources()?;
    let prepared = loaded.prepare(&sources.trees)?;
    assert!(prepared.candidates(&[1])?.rows.is_empty());
    assert_eq!(prepared.all_missing()?.rows.len(), 1);
    assert!(prepared.gap_root().is_some());
    let filled = publish(&backfill, Some(1), true, Some(gap_index), &BTreeMap::new()).await?;
    assert_eq!(filled.index_work.operations[0].association.index, primary);
    assert!(filled.index_work.operations[0].update.is_some());
    let loaded = indexing::load(
        backfill.coordinator().store(),
        filled.index_work.operations[0].owner,
        "uid",
        revisions(),
        262144,
    )
    .await?;
    let sources = loaded.sources()?;
    let prepared = loaded.prepare(&sources.trees)?;
    assert_eq!(prepared.candidates(&[1])?.rows.len(), 1);
    assert!(prepared.all_missing()?.rows.is_empty());
    assert!(prepared.gap_root().is_none());

    Ok(())
}

/// Keeps existing policy and rollback selections without authored maintenance.
///
/// # Errors
/// Preserves genuine native setup, admission, Original and publication failures.
/// # Panics
/// Panics if independently expected bytes, work or selected-state assertions fail.
pub(super) async fn selected_required_index_policy_and_rollback_retain_actual_view_selection()
-> TestResult {
    let repository = repository(2).await?;
    let (primary, nodes) = expected(Some(1))?;
    let first = publish(&repository, Some(1), true, Some(primary), &nodes).await?;
    let second = publish(&repository, Some(2), true, Some(primary), &BTreeMap::new()).await?;
    let guard = repository.coordinator().guard();
    let token = crate::ref_advance::tests::token();
    let policy = guard.admit_policy(REFERENCE, None, &token, "sdk").await?;
    assert!(policy.index_work.operations.is_empty());
    assert_eq!(policy.commit.identity(), second.record.commit);
    assert_eq!(policy.admission_profile.attribute_revision, 2);
    let rollback = guard
        .admit_rollback(REFERENCE, first.record.commit, &token, "sdk")
        .await?;
    assert!(rollback.index_work.namespace_loading.is_none());
    assert_eq!(rollback.commit.identity(), first.record.commit);
    assert_eq!(rollback.admission_profile.attribute_revision, 2);
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(second.record));
    Ok(())
}

/// Carries independently installed inputs through the real native adapter and ordinary reopen.
///
/// # Errors
/// Preserves genuine native setup, admission, Original and publication failures.
/// # Panics
/// Panics if independently expected bytes, work or selected-state assertions fail.
pub(super) async fn selected_required_index_adapter_and_reopen_keep_installed_inputs() -> TestResult
{
    use crate::domain::DomainNamespace;
    use crate::guard::{
        AuthoringNamespaceProfile, Guard, RecordedNamespaceProfile, RecordedNamespaceProfiles,
    };
    use crate::ref_advance::{CommitTiming, Coordinator};
    use crate::repository::Repository;
    use crate::store::{TokioClock, TokioLocalFs};
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    let repository = repository(2).await?;
    let (primary, nodes) = expected(Some(1))?;
    let first = publish(&repository, Some(1), true, Some(primary), &nodes).await?;
    let guard = repository.coordinator().guard();
    let authority = guard.configured_original_authority()?;
    let root = guard.store().root().to_owned();
    let owner = std::fs::symlink_metadata(authority.control())?.uid();
    let view = guard.verified_history(first.record.commit).await?;
    let commit = view.commit(&first.record.commit).ok_or_else(invalid)?;
    let context = terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?;
    let association = terrane_format::properties::semantics::associations::RecordedAssociation::new(
        first.record.commit,
        commit.commit().tree,
        context,
    );
    let profiles =
        RecordedNamespaceProfiles::new(vec![RecordedNamespaceProfile::new(association, 2)?])?;
    let new_guard = Guard::new_with_recorded_namespace_profiles_and_authoring(
        guard.store().clone(),
        TokioClock,
        guard.keys().to_vec(),
        guard.config().clone(),
        profiles,
        AuthoringNamespaceProfile::new(3, 3, &[], 2)?,
    );
    let reopened = Repository::reopen_native_retention(
        Coordinator::new(
            new_guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            TokioLocalFs,
        ),
        &DomainNamespace {
            root,
            domain: "public".into(),
        },
        authority.control(),
        owner,
    )
    .await?;
    let session = reopened
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    assert_eq!(session.record(), Some(&first.record));
    let history = reopened
        .coordinator()
        .guard()
        .verified_history(first.record.commit)
        .await?;
    let actual = history.commit(&first.record.commit).ok_or_else(invalid)?;
    let (_, profile) = reopened
        .coordinator()
        .guard()
        .selected_view_profile(actual, HistoryObservation::default())?;
    assert_eq!(profile.attribute_revision, 2);
    assert_eq!(
        reopened.coordinator().store().ref_get(REFERENCE).await?,
        Some(first.record)
    );
    Ok(())
}

fn revisions() -> SemanticRevisions {
    SemanticRevisions {
        property: 3,
        attribute: 2,
        tree: 1,
    }
}

fn refused(
    result: Result<crate::repository::CommitReport, crate::repository::Error>,
) -> StoreFailure {
    match result {
        Err(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(
            failure,
        )))
        | Err(crate::repository::Error::Store(failure)) => failure,
        other => panic!("expected the actual scoped store refusal, got {other:?}"),
    }
}
