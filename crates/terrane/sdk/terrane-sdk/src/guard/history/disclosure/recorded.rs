//! Dispatches disclosure completion through the installed view interpretation.
//!
//! Planning retains only an ordinary dependency list. The parent completes those
//! dependencies, rechecks Original controls and retains source roles before it
//! records successful view consumption. Neither an association table nor this
//! dispatch supplies current operation authority.

use terrane_format::{
    identity::Digest,
    properties::Defaults,
    provenance::{
        DisclosureAuthority, DisclosureCandidate, OriginalBootstrapPolicy, VerifiedDisclosureBatch,
        VerifiedHistory,
    },
};

use crate::store::StoreFailure;

use super::invalid;

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// Plans ordinary dependencies with exact installed, known and candidate meanings.
///
/// # Errors
/// Preserves genuine certificate, original-root and retained-scope refusals.
pub(super) fn mixed_dependencies(
    history: &VerifiedHistory,
    view: Digest,
    authorities: &[DisclosureAuthority<'_>],
    defaults: Defaults<'_>,
    selections: &terrane_format::properties::semantics::selections::ViewPropertySelections,
) -> Result<Vec<Digest>, StoreFailure> {
    let candidate = DisclosureCandidate::new_with_property_selections(
        history,
        view,
        authorities,
        defaults,
        selections,
    )
    .map_err(|_| invalid())?;
    Ok(candidate.required_commits().to_vec())
}

/// Completes mixed history with independently checked Original bootstrap evidence.
///
/// # Errors
/// Preserves dependency, certificate, producer, root-scope and bootstrap failures.
pub(super) fn mixed_finish<'a>(
    history: &VerifiedHistory,
    view: Digest,
    authorities: &[DisclosureAuthority<'_>],
    defaults: Defaults<'a>,
    selections: &terrane_format::properties::semantics::selections::ViewPropertySelections,
    original_authority: &'a str,
    bootstrap: OriginalBootstrapPolicy<'a>,
) -> Result<(VerifiedHistory, VerifiedDisclosureBatch), StoreFailure> {
    DisclosureCandidate::new_with_property_selections_and_bootstrap(
        history,
        view,
        authorities,
        defaults,
        selections,
        original_authority,
        bootstrap,
    )
    .map_err(|_| invalid())?
    .finish()
    .map_err(|_| invalid())
}
