//! Derives fresh fork occurrence data from genuinely qualified identical inputs.
//!
//! ALG-32 preserves the exact source namespace and its completed signed history.
//! The private producer therefore verifies the exact algebra fork, fresh signed
//! candidate and independently checked destination Original before deriving new
//! candidate rows. It does not construct U3 Pending/CompletedViewUse values or
//! label a new ordinary history walk complete. Prior dependencies remain intact.

use super::*;
use terrane_core::gc::publication::evidence::LineageUsedInputs;

/// Extends checked source data only after genuine fresh fork admission and retention.
///
/// # Errors
/// Rejects changed signed tree/parent/profile, introduction receipts, Original
/// context, conflicting candidate rows or unsupported current actual semantics.
pub(super) fn extend_completed_fork<S, C, F: LocalFs>(
    guard: &Guard<S, C>,
    qualified: &QualifiedSource<'_, '_, F>,
    admitted: &crate::guard::AdmittedCommit,
    original: &crate::guard::OriginalCommitContext,
    used: &mut LineageUsedInputs,
) -> Result<(), StoreFailure> {
    let context = crate::guard::cold_fork::candidate_context(guard, admitted)?;
    if original.commit() != &admitted.commit.identity()
        || admitted.commit.commit().tree != qualified.commit().commit().tree
        || admitted.commit.commit().parents != [qualified.commit().identity()]
        || context.registries != *qualified.policies.source_profile()?
        || used.views != qualified.policies.lineage.used.views
        || used.view_interpretations != qualified.policies.lineage.used.view_interpretations
    {
        return Err(invalid());
    }
    let identity = admitted.commit.identity();
    if used.views.iter().any(|view| view.view == identity) {
        return Err(invalid());
    }
    for view in qualified.policies.source_views() {
        let mut candidate = view.clone();
        candidate.view = identity;
        // Full equal Legacy semantics and the exact signed source tree retain
        // all canonical occurrences and layers; no ancestor is forged/decoded.
        used.views.push(candidate);
    }
    let contexts = used.view_interpretations.as_mut().ok_or_else(invalid)?;
    if contexts.iter().any(|old| old.view == context.view) {
        return Err(invalid());
    }
    contexts.push(context);
    contexts.sort_by_key(|row| row.view);
    if !used
        .check_supported_view_contexts()
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(())
}
