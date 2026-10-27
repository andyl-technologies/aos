//! Retains caller-supplied immutable-read interpretation without granting authority.
//!
//! Selection follows checked view/root evidence. Explicit configuration never
//! falls back to legacy semantics, including when its table is empty.

use std::sync::Arc;

#[cfg(test)]
use terrane_format::properties::semantics::associations::RecordedAssociations;

use terrane_format::{
    identity::Digest,
    properties::semantics::associations::RecordedAssociation,
    properties::{Defaults, EffectiveProperties, RootLayer},
    provenance::{Selector, TrustContext, VerifiedHistory},
};

#[cfg(feature = "std")]
use terrane_format::provenance::{self, OriginalBootstrapPolicy, VerifiedRootScope};

use super::{TreeEvidence, domain_label, invalid};
use crate::store::StoreFailure;
use terrane_format::properties::selected::Selection;

pub(super) mod profiles;

#[cfg(test)]
mod tests;

// This fixture family loads canonical evidence through the Tokio test runtime.
// Its three mandatory selectors execute in the owning Tokio gate profile.
#[cfg(all(test, feature = "tokio"))]
mod historical_tests;

/// Distinguishes deliberate legacy installation from immutable explicit input.
#[derive(Clone)]
#[cfg(test)]
pub(super) enum ReadInterpretations {
    /// Deliberately retains existing legacy interpretation entrypoints.
    #[cfg(feature = "std")]
    Legacy,
    /// Retains explicit immutable input, including an empty refusal-only table.
    Recorded(Arc<RecordedAssociations>),
}

/// Retains the exact interpretation selected for a checked immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SelectedReadInterpretation {
    /// Uses the intentionally selected legacy constructor behavior.
    Legacy,
    /// Owns independently supplied view/root configuration, not authority.
    Recorded(Arc<RecordedAssociation>),
}

#[cfg(test)]
impl ReadInterpretations {
    /// Selects only the exact checked view and original root.
    ///
    /// # Errors
    /// Rejects absent views or mismatched roots in explicit mode.
    pub(super) fn select(
        &self,
        view: Digest,
        root: Digest,
    ) -> Result<SelectedReadInterpretation, StoreFailure> {
        match self {
            #[cfg(feature = "std")]
            Self::Legacy => Ok(SelectedReadInterpretation::Legacy),
            Self::Recorded(table) => table
                .select(view, root)
                .map(|entry| SelectedReadInterpretation::Recorded(Arc::new(entry.clone())))
                .map_err(configuration_failure),
        }
    }

    /// Checks captured interpretation against this Guard's immutable installation.
    ///
    /// Equivalent independently installed entries agree; shared physical roots
    /// alone cannot downgrade a captured explicit interpretation to legacy.
    ///
    /// # Errors
    /// Rejects mode, view, root, revision or preservation-registration mismatch.
    #[cfg(feature = "std")]
    pub(super) fn check_retained(
        &self,
        selected: &SelectedReadInterpretation,
        view: Digest,
        root: Digest,
    ) -> Result<(), StoreFailure> {
        if self.select(view, root)? != *selected {
            return Err(invalid());
        }
        Ok(())
    }
}

impl SelectedReadInterpretation {
    /// Projects checked selector input without supplying an association override.
    ///
    /// # Errors
    /// Rejects an unnormalized Active mode; the owning selector normalizes that
    /// explicit constructor before this ordinary projection.
    pub(in crate::guard) fn from_selection(
        view: Digest,
        original_root: Digest,
        selected: Selection,
    ) -> Result<Self, StoreFailure> {
        match selected {
            Selection::Legacy => Ok(Self::Legacy),
            Selection::Recorded(context) => Ok(Self::Recorded(Arc::new(RecordedAssociation::new(
                view,
                original_root,
                context,
            )))),
            Selection::Active => Err(invalid()),
        }
    }

    /// Copies exact retained ordinary semantics without granting history authority.
    pub(crate) fn selection(&self) -> Selection {
        match self {
            Self::Legacy => Selection::Legacy,
            Self::Recorded(entry) => Selection::Recorded(entry.context().clone()),
        }
    }

    fn check_history_selection(
        &self,
        history: &VerifiedHistory,
        view: Digest,
    ) -> Result<(), StoreFailure> {
        if history
            .property_selection(view)
            .map_err(configuration_failure)?
            != self.selection()
        {
            return Err(invalid());
        }
        if let Self::Recorded(entry) = self {
            let actual = history.commit(&view).ok_or_else(invalid)?;
            if entry.view() != view || entry.original_root() != actual.commit().tree {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Witnesses historical occurrences under one enclosing interpretation.
    ///
    /// Removed-claim comparisons deliberately reuse the candidate's selected
    /// interpretation for prior evidence. Independently verifying that prior
    /// view selects its own association; this calculation does not authenticate it.
    ///
    /// # Errors
    /// Rejects invalid occurrence layers, domain properties, or duplicate
    /// occurrence/path-domain units. Repeated physical roots remain valid.
    pub(super) fn historical_roots(
        &self,
        evidence: &TreeEvidence,
        minimum: u64,
        defaults: Defaults<'_>,
    ) -> Result<Vec<(Vec<u8>, String)>, StoreFailure> {
        let mut roots = Vec::new();
        for occurrence in evidence.occurrences(minimum)? {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = self.resolve(&layers, defaults)?;
            roots.push((
                occurrence.path,
                domain_label(&effective)
                    .map_err(configuration_failure)?
                    .to_owned(),
            ));
        }
        roots.sort();
        if roots.is_empty() || roots.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid());
        }
        Ok(roots)
    }

    /// Verifies original scope with the retained caller-selected interpretation.
    ///
    /// The caller supplies checked original authority and bootstrap input. Both
    /// modes invoke the existing authenticated core verifier before retention.
    ///
    /// # Errors
    /// Preserves checked-history, original-authority, bootstrap, scope and
    /// interpretation mismatch refusals without switching constructor modes.
    #[cfg(feature = "std")]
    pub(super) fn verify_original_scope(
        &self,
        history: &mut VerifiedHistory,
        view: Digest,
        defaults: Defaults<'_>,
        authority: &str,
        bootstrap: OriginalBootstrapPolicy<'_>,
    ) -> Result<VerifiedRootScope, StoreFailure> {
        match self {
            Self::Legacy => {
                self.check_history_selection(history, view)?;
                provenance::verify_root_context_with_bootstrap(
                    history, view, defaults, authority, bootstrap,
                )
                .map_err(configuration_failure)
            }
            Self::Recorded(entry) => {
                VerifiedRootScope::verify_with_recorded_properties_and_bootstrap(
                    history,
                    view,
                    defaults,
                    Some(entry.as_ref()),
                    authority,
                    bootstrap,
                )
                .map_err(configuration_failure)
            }
        }
    }

    /// Resolves immutable layers under the same retained interpretation.
    ///
    /// Effective values borrow only the supplied layers/defaults, never the
    /// temporary preservation-name slice reconstructed by `with_context`.
    ///
    /// # Errors
    /// Preserves property validation errors, including graft placement refusal.
    pub(crate) fn resolve<'p>(
        &self,
        layers: &[RootLayer<'p>],
        defaults: Defaults<'p>,
    ) -> Result<EffectiveProperties<'p>, StoreFailure> {
        match self {
            Self::Legacy => Selection::Legacy
                .resolve(layers, defaults)
                .map_err(configuration_failure),
            Self::Recorded(entry) => entry
                .with_context(|context| context.resolve(layers, defaults))
                .map_err(configuration_failure)?
                .map_err(configuration_failure),
        }
    }

    /// Constructs an owned evaluator from checked history and retained input.
    ///
    /// Configuration supplies interpretation only. The core constructor checks
    /// verified history and the actual immutable view/original-root association.
    ///
    /// # Errors
    /// Rejects missing checked history, mismatched selected roots/views or invalid
    /// recorded configuration, without switching constructor modes.
    pub(crate) fn evaluator(
        &self,
        history: &VerifiedHistory,
        selection: (Digest, Digest),
        selector: Selector,
        domain: &str,
        baseline: Option<&str>,
    ) -> Result<TrustContext, StoreFailure> {
        let (view, root) = selection;
        match self {
            Self::Legacy => {
                self.check_history_selection(history, view)?;
                TrustContext::new(history, view, selector, domain, baseline)
                    .map_err(configuration_failure)
            }
            Self::Recorded(entry) => {
                if entry.view() != view || entry.original_root() != root {
                    return Err(invalid());
                }
                entry
                    .with_context(|context| {
                        TrustContext::new_with_recorded(
                            history,
                            view,
                            selector,
                            domain,
                            baseline,
                            Some((entry.view(), entry.original_root(), context.clone())),
                        )
                    })
                    .map_err(configuration_failure)?
                    .map_err(configuration_failure)
            }
        }
    }
}

fn configuration_failure(error: impl std::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(invalid().kind().clone(), error)
}
