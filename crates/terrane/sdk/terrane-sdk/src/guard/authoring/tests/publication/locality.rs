//! Measures native affected graft selection and separately charged validation capture.
//!
//! All publications use the genuine signed Repository producer. Exhaustive pure
//! reference construction and output reads sit outside measured maintenance.

mod support;

use super::super::TestResult;
use super::support::{REFERENCE, repository};
use crate::guard::invalid;
use crate::repository::CommitReport;
use crate::store::{ContentStore, RefStore, StoreFailure};
use std::error::Error as _;
use terrane_format::{
    identity::{IdentityKind, TERRANE_V1},
    indexing::{evaluation, incremental::PopulationMode},
};

/// Proves selection does not scan unrelated containing entries as populations grow.
///
/// # Errors
/// Preserves genuine native publication, canonical model and original history failures.
/// # Panics
/// Panics if canonical outputs or actually executed locality counters disagree.
#[tokio::test]
async fn native_index_propagation_selects_only_affected_immutable_graft_entries() -> TestResult {
    let mut validation_entries = Vec::new();
    for population in [64, 256, 1024] {
        let repository = repository(2).await?;
        let (first, before) = support::publish(&repository, 1, None, population, 1).await?;
        let (second, expected) =
            support::publish(&repository, 2, Some(&first), population, 1).await?;
        support::assert_outputs(&repository, &second, &expected).await?;
        support::assert_immutable(&repository, &before).await?;
        assert_existing(&second, 1)?;
        assert_graft_validation(&second, population, 1)?;

        let work = &second.index_work;
        validation_entries.push(work.graft_validation.ok_or_else(invalid)?.entry_visits);

        let preparation = work.graft_preparation.ok_or_else(invalid)?;
        assert_eq!(preparation.owners, 3);
        assert_eq!(preparation.owner_occurrences, 3);
        assert_eq!(preparation.entry_visits, 0);
        assert_eq!(preparation.nested_entry_visits, 0);
        assert_eq!(preparation.graft_slots, 2);
        assert_eq!(preparation.graft_occurrences, 2);

        let propagation = work.graft_propagation;
        assert_eq!(propagation.changed_targets, 2);
        assert_eq!(propagation.target_lookups, 2);
        assert_eq!(propagation.address_links, 1);
        assert_eq!(propagation.affected_occurrences, 1);
        assert_eq!(propagation.selected_entries, 1);
        assert_eq!(propagation.entry_lookups, 1);
        assert_eq!(propagation.nested_entry_visits, 1);
        assert_eq!(propagation.replacement_lookups, 1);
        assert_eq!(propagation.replaced_graft_slots, 1);
        assert_eq!(propagation.edited_entries, 1);
        assert_eq!(work.propagation.len(), 1);
        assert!(work.namespace_reconstruction.ok_or_else(invalid)?.entries >= population);
    }
    assert_eq!(validation_entries, [68, 260, 1028]);
    Ok(())
}

/// Expands each genuine repeated graft and refuses unsupported conditional coverage.
///
/// # Errors
/// Preserves real native input, publication and selected-state read failures.
/// # Panics
/// Panics if repeated routes collapse, a Conflict is admitted, or its typed cause changes.
#[tokio::test]
async fn native_index_propagation_preserves_repeated_grafts_and_conflict_refusal() -> TestResult {
    let repository = repository(2).await?;
    let (first, before) = support::publish(&repository, 1, None, 8, 2).await?;
    let (second, expected) = support::publish(&repository, 2, Some(&first), 8, 2).await?;
    support::assert_outputs(&repository, &second, &expected).await?;
    support::assert_immutable(&repository, &before).await?;
    assert_existing(&second, 2)?;
    assert_graft_validation(&second, 8, 2)?;

    let work = &second.index_work;
    let preparation = work.graft_preparation.ok_or_else(invalid)?;
    assert_eq!(preparation.owners, 3);
    assert_eq!(preparation.owner_occurrences, 4);
    assert_eq!(preparation.entry_visits, 0);
    assert_eq!(preparation.nested_entry_visits, 0);
    assert_eq!(preparation.graft_slots, 3);
    assert_eq!(preparation.graft_occurrences, 3);
    assert_eq!(work.graft_propagation.address_links, 2);
    assert_eq!(work.graft_propagation.affected_occurrences, 2);
    assert_eq!(work.graft_propagation.selected_entries, 2);
    assert_eq!(work.graft_propagation.entry_lookups, 2);
    assert_eq!(work.graft_propagation.replaced_graft_slots, 2);
    assert_eq!(work.graft_propagation.edited_entries, 2);
    let child = work
        .operations
        .iter()
        .find(|operation| operation.owner == expected.child)
        .ok_or_else(invalid)?;
    assert_eq!(child.paths, vec![b"/g01".to_vec(), b"/g00".to_vec()]);

    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let mut candidate = support::candidate(
        &repository,
        vec![second.record.commit],
        2,
        Some(&second),
        8,
        2,
    )
    .await?;
    let conflict = support::conflict(&candidate)?;
    let owner = conflict.root();
    let mut request = candidate.request.take().ok_or_else(invalid)?;
    request.commit.tree = owner;
    let failure = refused(
        repository
            .commit_with_report(&mut session, conflict, request)
            .await,
    );
    assert_eq!(failure.kind(), invalid().kind());
    assert_eq!(
        failure
            .source()
            .and_then(|cause| cause.downcast_ref::<evaluation::Error>()),
        Some(&evaluation::Error::Incomplete)
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second.record)
    );
    let identity = TERRANE_V1.from_digest(IdentityKind::Node, &owner)?;
    assert_eq!(
        repository.coordinator().store().has(&[identity]).await?,
        vec![false]
    );
    Ok(())
}

/// Retains equal subtrees and keeps validation capture outside discovery delta and B.
///
/// # Errors
/// Preserves signed native publication, full history and authority checking failures.
/// # Panics
/// Panics if equal immutable targets produce edits or policy lanes execute maintenance.
#[tokio::test]
async fn native_index_propagation_keeps_preparation_outside_delta_and_boundary_work() -> TestResult
{
    let repository = repository(2).await?;
    let (first, expected) = support::publish(&repository, 1, None, 64, 2).await?;
    let (equal, same) = support::publish(&repository, 1, Some(&first), 64, 2).await?;
    support::assert_outputs(&repository, &equal, &same).await?;
    assert_eq!(same.final_root, expected.final_root);
    assert_eq!(same.child, expected.child);
    assert_eq!(same.stable, expected.stable);
    assert_graft_validation(&equal, 64, 2)?;

    let work = &equal.index_work;
    let preparation = work.graft_preparation.ok_or_else(invalid)?;
    assert_eq!(preparation.owners, 3);
    assert_eq!(preparation.owner_occurrences, 4);
    assert_eq!(preparation.entry_visits, 0);
    assert_eq!(preparation.nested_entry_visits, 0);
    assert_eq!(preparation.graft_slots, 3);
    assert_eq!(preparation.graft_occurrences, 3);
    assert_eq!(
        work.graft_propagation,
        crate::guard::IndexGraftPropagationWork::default()
    );
    assert!(work.propagation.is_empty());
    assert!(work.namespace_reconstruction.ok_or_else(invalid)?.entries >= 69);
    for operation in &work.operations {
        assert!(operation.initialization.is_none());
        let update = operation.update.as_ref().ok_or_else(invalid)?;
        assert_eq!(update.mode, PopulationMode::Existing);
        assert_eq!(
            (update.delta_input, update.delta_data, update.delta_route),
            (0, 0, 0)
        );
        assert_eq!(operation.boundary, Some(update.boundary_cost()?));
        assert!(operation.old_source.ok_or_else(invalid)?.entries > 0);
        assert!(operation.new_source.entries > 0);
        assert!(operation.old_index.is_some());
    }
    let guard = repository.coordinator().guard();
    let token = crate::ref_advance::tests::token();
    let policy = guard.admit_policy(REFERENCE, None, &token, "sdk").await?;
    assert_eq!(policy.commit.identity(), equal.record.commit);
    assert!(policy.index_work.namespace_loading.is_none());
    assert!(policy.index_work.graft_validation.is_none());
    assert!(policy.index_work.graft_preparation.is_none());
    assert!(policy.index_work.operations.is_empty());
    let rollback = guard
        .admit_rollback(REFERENCE, first.record.commit, &token, "sdk")
        .await?;
    assert!(rollback.index_work.namespace_loading.is_none());
    assert!(rollback.index_work.graft_validation.is_none());
    assert!(rollback.index_work.graft_preparation.is_none());
    assert!(rollback.index_work.operations.is_empty());
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(equal.record));
    Ok(())
}

/// Checks actual canonical validation visits and physical address copies.
fn assert_graft_validation(report: &CommitReport, population: usize, repeats: usize) -> TestResult {
    let validation = report.index_work.graft_validation.ok_or_else(invalid)?;
    assert_eq!(validation.owners, 3);
    assert!(validation.node_visits >= validation.owners);

    // The parent has population files, repeated child grafts and one stable
    // graft; each distinct child contributes one regular-file entry.
    assert_eq!(validation.entry_visits, population + repeats + 3);
    assert_eq!(validation.nested_entry_visits, validation.entry_visits);
    assert_eq!(validation.graft_slots, repeats + 1);
    assert_eq!(validation.addresses, validation.graft_slots);
    assert_eq!(
        validation.key_bytes,
        repeats * b"g00".len() + b"unchanged".len()
    );

    // Repeated placements retain separate addresses while the depth
    // certificate processes the two distinct child edges.
    assert!(validation.depth_checks >= validation.owners);
    assert_eq!(validation.depth_edges, 2);
    Ok(())
}

fn assert_existing(report: &CommitReport, repeats: usize) -> TestResult {
    assert_eq!(report.index_work.operations.len(), 2);
    for operation in &report.index_work.operations {
        assert!(operation.initialization.is_none());
        assert!(operation.old_loading.is_some());
        assert!(operation.old_inputs.is_some());
        assert!(operation.old_reconstruction.is_some());
        assert!(operation.old_source.is_some());
        assert!(operation.old_index.is_some());
        let update = operation.update.as_ref().ok_or_else(invalid)?;
        assert_eq!(update.mode, PopulationMode::Existing);
        let root = operation.paths == [b"/".to_vec()];
        assert_eq!(update.delta_data, if root { repeats } else { 1 });
        assert!(update.delta_input >= update.delta_data);
        assert!(update.delta_route > 0);
        assert_eq!(operation.boundary, Some(update.boundary_cost()?));
        assert!(operation.export.nodes > 0);
    }
    Ok(())
}

fn refused(result: Result<CommitReport, crate::repository::Error>) -> StoreFailure {
    match result {
        Err(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(
            failure,
        )))
        | Err(crate::repository::Error::Store(failure)) => failure,
        other => panic!("expected exact native index refusal, got {other:?}"),
    }
}
