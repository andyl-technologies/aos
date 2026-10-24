//! Rechecks exact used meanings, signed source bytes and actual Original contexts.
//!
//! Ancestor contexts are independently native-checked administrative evidence.
//! They are never converted into invented VerifiedCommits or completed walks.

use std::collections::BTreeSet;

use terrane_format::auth::RequestRoot;
use terrane_format::gc::publication::evidence::{
    CheckedLineage, ControlKind, GuardSnapshot, OriginalAssociation, OriginalImport,
};
use terrane_format::provenance;
use terrane_format::refs::Commit;

use crate::bucket::publication::SelectedObservation;
use crate::guard::cold_fork::occurrence_domain;
use crate::guard::{
    ConsumedResolver, Guard, HistoryObservation, OriginalAuthority, RetainedControls,
    consumed_registration, invalid,
};
use crate::store::{Clock, Store, StoreFailure};

/// Compares the exact used trust rows and complete configured interpretation.
///
/// Unrelated additive rows do not become dependencies. Retirement bounds and
/// every actually used issuer/disclosure row must remain exactly unchanged.
///
/// # Errors
/// Rejects changed configured semantics or absent or altered used trust rows.
pub(super) fn check_used_guard(
    lineage: &CheckedLineage,
    current: &GuardSnapshot,
) -> Result<(), StoreFailure> {
    if lineage.used.configuration != current.configuration
        || lineage.used.registries != current.registries
        || lineage
            .used
            .issuers
            .iter()
            .any(|row| !current.issuers.contains(row))
        || lineage
            .used
            .disclosures
            .iter()
            .any(|row| !current.disclosures.contains(row))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Compares every distinct used view against independently installed full inputs.
///
/// Repeated policy occurrences remain untouched in the carried lineage. Only
/// the redundant selection comparison is deduplicated by immutable view ID.
///
/// # Errors
/// Rejects missing strict selections, changed modes, roots or any registry field.
pub(super) fn check_selected_inputs<S, C>(
    guard: &Guard<S, C>,
    lineage: &CheckedLineage,
) -> Result<(), StoreFailure> {
    let mut distinct = BTreeSet::new();
    for view in &lineage.used.views {
        if distinct.insert(view.view) {
            super::super::cold_fork::compare_view_inputs(guard, lineage, view)?;
        }
    }
    Ok(())
}

/// Qualifies one genuine prior completed source under the actual held update.
///
/// # Errors
/// Rejects unavailable or changed actual Original contexts/control pins, changed
/// full selections, invalid source signatures or root claims and profile errors.
pub(super) async fn qualify<S: Store, C: Clock>(
    current: &Guard<S, C>,
    configured: &Guard<(), ()>,
    authority: &OriginalAuthority,
    observed: &SelectedObservation<'_>,
    retained: &RetainedControls,
    lineage: &CheckedLineage,
) -> Result<(), StoreFailure> {
    let commit = Commit::decode(&lineage.commit_bytes).map_err(|_| invalid())?;
    let source_index = super::super::cold_fork::check_views(lineage, &commit)?;
    check_selected_inputs(current, lineage)?;
    check_selected_inputs(configured, lineage)?;

    let originals = ConsumedResolver::new(configured, authority)?;
    originals.registration(authority)?;
    for identity in original_dependencies(authority, retained, lineage)? {
        let original = configured.original_commit(&identity)?;
        if original.commit() != &identity || current.original_commit(&identity)? != original {
            return Err(invalid());
        }
        configured
            .revalidate_original_context(&original, HistoryObservation::held(observed.identity()))
            .await?;
        originals.original(&original)?;
    }
    // Only freshly native-checked opaque contexts generate this pin set. This
    // resolver records no fabricated CompletedViewUse and creates no history.
    // Extra unrelated association-table rows never enter the comparison.
    if originals.finish()?.controls != lineage.controls {
        return Err(invalid());
    }

    let source_original = configured.original_commit(&lineage.commit_id)?;
    let baseline = source_original.baseline();
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or_else(invalid)?;
    if lineage.original != consumed_registration(baseline.authority())
        || context.reference() != baseline.reference()
        || commit.provenance.writer_epoch != baseline.epoch()
        || commit.profile_pair.chunk_profile != current.config().chunk_profile_name
    {
        return Err(invalid());
    }

    check_signed_roots(current, lineage, &commit, source_index)?;
    let roots = context
        .roots()
        .iter()
        .map(|claim| RequestRoot {
            path: claim.path(),
            domain: claim.domain(),
        })
        .collect::<Vec<_>>();
    let historical_keys = source_original.historical_keys()?;
    let verified = provenance::verify_history(
        &commit,
        historical_keys.as_deref().unwrap_or(current.keys()),
        &roots,
        &[(baseline.reference(), baseline.epoch())],
    )
    .map_err(|_| invalid())?;
    if verified.identity() != lineage.commit_id {
        return Err(invalid());
    }
    current
        .check_cold_fork_source_profile(&verified, HistoryObservation::held(observed.identity()))?;
    check_selected_inputs(current, lineage)
}

fn original_dependencies(
    authority: &OriginalAuthority,
    retained: &RetainedControls,
    lineage: &CheckedLineage,
) -> Result<BTreeSet<[u8; 32]>, StoreFailure> {
    let mut identities = lineage
        .used
        .views
        .iter()
        .map(|view| view.view)
        .collect::<BTreeSet<_>>();
    // History can consume an Original association without using that commit's
    // namespace. Retained bytes select an already factory-checked opaque context;
    // the native recheck, not this ordinary ID extraction, validates its meaning.
    for pin in &lineage.controls {
        let path = authority.control().join(&pin.key);
        let record = retained
            .records()
            .iter()
            .find(|record| record.path() == path)
            .ok_or_else(invalid)?;
        pin.check_record(record.bytes()).map_err(|_| invalid())?;
        match pin.kind {
            ControlKind::Association => {
                identities.insert(
                    OriginalAssociation::decode(record.bytes())
                        .map_err(|_| invalid())?
                        .commit,
                );
            }
            ControlKind::Import => {
                identities.insert(
                    OriginalImport::decode(record.bytes())
                        .map_err(|_| invalid())?
                        .association
                        .commit,
                );
            }
            ControlKind::Registration
            | ControlKind::Bootstrap
            | ControlKind::ImportBinding
            | ControlKind::ImportTrust => {}
        }
    }
    Ok(identities)
}

fn check_signed_roots<S, C>(
    current: &Guard<S, C>,
    lineage: &CheckedLineage,
    commit: &Commit,
    source_index: usize,
) -> Result<(), StoreFailure> {
    let has_disclosures = commit
        .profile_pair
        .entry_receipts
        .iter()
        .flatten()
        .any(|receipt| receipt.disclosure_proof.is_some());
    if has_disclosures {
        // The genuine selected prior completion already checked the complete
        // certificate graph. Its exact used roles/import pins were rechecked
        // above. Ordinary history authenticates such signed claims directly;
        // private audit parents cannot be promoted to public root authority.
        return Ok(());
    }

    let candidate = lineage.used.views.get(source_index).ok_or_else(invalid)?;
    let previous = commit.parents.first().copied();
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or_else(invalid)?;
    for claim in context.roots() {
        let mut witnessed = false;
        for view in lineage
            .used
            .views
            .iter()
            .filter(|view| view.view == candidate.view || Some(view.view) == previous)
        {
            let selected = current.cold_fork_interpretation(view)?;
            for root in &view.roots {
                if root.path == claim.path()
                    && occurrence_domain(root, view, &lineage.used.configuration, &selected)?
                        == claim.domain()
                {
                    witnessed = true;
                }
            }
        }
        if !witnessed {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Preserves the original physical receipt rather than accepting refreshed bytes.
///
/// # Errors
/// Rejects replaced ancestors, directory/lock or record incarnations and bytes.
pub(super) fn check_controls(
    previous: &RetainedControls,
    current: &RetainedControls,
) -> Result<(), StoreFailure> {
    if previous.directory() != current.directory()
        || previous.owner() != current.owner()
        || previous.identities() != current.identities()
        || previous.ancestors() != current.ancestors()
        || previous.records().len() != current.records().len()
        || previous
            .records()
            .iter()
            .zip(current.records())
            .any(|(previous, current)| {
                previous.path() != current.path()
                    || previous.identity() != current.identity()
                    || previous.bytes() != current.bytes()
            })
    {
        return Err(invalid());
    }
    Ok(())
}
