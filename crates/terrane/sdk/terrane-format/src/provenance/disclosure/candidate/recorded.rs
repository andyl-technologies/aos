//! Retains immutable ordinary interpretation inputs for real disclosure verification.
//!
//! Selection uses signed view/root pairs and never infers registrations from
//! decoded claims. This module creates no scope or boundary authority.

use super::{Defaults, Digest, OriginalBootstrapPolicy, Rejected, VerifiedHistory};
use crate::properties::semantics::{
    RecordedContext,
    associations::{RecordedAssociation, RecordedAssociations},
    selections::ViewPropertySelections,
};
use crate::provenance::{
    VerifiedRootScope, verify_root_context, verify_root_context_with_bootstrap,
};

/// Keeps deliberate compatibility mode distinct from explicit recorded selection.
pub(in crate::provenance::disclosure) enum Interpretation {
    /// Preserves the existing current constructors and merged-layer calculation.
    Current,
    /// Owns independently justified per-view original-root interpretations.
    Recorded(RecordedAssociations),
    /// Owns independently selected Legacy and Recorded views in one history.
    Mixed(ViewPropertySelections),
}

impl Interpretation {
    fn association(
        &self,
        history: &VerifiedHistory,
        view: Digest,
    ) -> Result<Option<&RecordedAssociation>, Rejected> {
        let record = history.commit(&view).ok_or(Rejected)?;
        let installed = history.view_selection(view)?;
        match self {
            Self::Current => Ok(None),
            Self::Recorded(associations) => associations
                .select(record.identity(), record.commit().tree)
                .map_err(|_| Rejected)
                .and_then(|association| {
                    if installed
                        == crate::properties::selected::Selection::Recorded(
                            association.context().clone(),
                        )
                    {
                        Ok(Some(association))
                    } else {
                        Err(Rejected)
                    }
                }),
            Self::Mixed(selections) => selections
                .select(record.identity(), record.commit().tree)
                .map_err(|_| Rejected)
                .and_then(|association| {
                    let expected = association
                        .map(|a| {
                            crate::properties::selected::Selection::Recorded(a.context().clone())
                        })
                        .unwrap_or(crate::properties::selected::Selection::Legacy);
                    if installed == expected {
                        Ok(association)
                    } else {
                        Err(Rejected)
                    }
                }),
        }
    }

    /// Supplies the exact view's borrowed interpretation without exposing authority.
    ///
    /// # Errors
    /// Rejects missing or mismatched associations and preserves the action's
    /// canonical, property and path failures.
    ///
    /// # Panics
    /// Propagates a panic from the supplied action.
    pub(in crate::provenance::disclosure) fn with_properties<T>(
        &self,
        history: &VerifiedHistory,
        view: Digest,
        action: impl for<'a> FnOnce(Option<&'a RecordedContext>) -> Result<T, Rejected>,
    ) -> Result<T, Rejected> {
        if matches!(self, Self::Current) {
            return match history.view_selection(view)? {
                crate::properties::selected::Selection::Recorded(context) => action(Some(&context)),
                _ => action(None),
            };
        }
        match self.association(history, view)? {
            None => action(None),
            Some(selected) => selected
                .with_context(|context| action(Some(context)))
                .map_err(|_| Rejected)?,
        }
    }

    /// Refuses an already retained modern scope with a different mode or fence.
    ///
    /// # Errors
    /// Rejects unavailable views, inconsistent associations or a conflicting
    /// completed scope. An absent scope remains for the actual verifier to check.
    pub(in crate::provenance::disclosure) fn check_existing_scope(
        &self,
        history: &VerifiedHistory,
        view: Digest,
    ) -> Result<(), Rejected> {
        let selected = self.association(history, view)?;
        if history.root_scopes.get(&view).is_some_and(|scope| {
            if matches!(self, Self::Current) {
                match history.view_selection(view) {
                    Ok(selection) => !scope.matches_selection(&selection),
                    Err(_) => true,
                }
            } else {
                !scope.matches_properties(selected)
            }
        }) {
            return Err(Rejected);
        }
        Ok(())
    }

    /// Requires genuine completed modern scope under the exact consumed selection.
    ///
    /// Contextless legacy records keep their independently verified original
    /// authentication contract; no modern scope is fabricated for them.
    ///
    /// # Errors
    /// Rejects unavailable or unfinished modern evidence, missing associations,
    /// and conflicting current/recorded modes, revisions or preservation sets.
    pub(in crate::provenance::disclosure) fn check_scope(
        &self,
        history: &VerifiedHistory,
        view: Digest,
    ) -> Result<(), Rejected> {
        history.require_root_context_validation(view)?;
        self.check_existing_scope(history, view)?;
        if history
            .commit(&view)
            .ok_or(Rejected)?
            .commit()
            .profile_pair
            .commit_context
            .is_some()
            && !history.root_scopes.contains_key(&view)
        {
            return Err(Rejected);
        }
        Ok(())
    }

    /// Delegates original authorization to the existing authenticated scope verifier.
    ///
    /// One enclosing candidate context governs both comparison sides and every
    /// claim/Admin prefix. Each prior view is independently verified beforehand.
    ///
    /// # Errors
    /// Preserves all actual token, original authority, bootstrap, canonical,
    /// property and retained-interpretation failures of the selected verifier.
    pub(in crate::provenance::disclosure) fn verify(
        &self,
        history: &mut VerifiedHistory,
        view: Digest,
        defaults: Defaults<'_>,
        bootstrap: Option<(&str, OriginalBootstrapPolicy<'_>)>,
    ) -> Result<(), Rejected> {
        let selected = self.association(history, view)?;
        match (selected, bootstrap) {
            (None, None) => {
                verify_root_context(history, view, defaults)?;
            }
            (None, Some((authority, policy))) => {
                verify_root_context_with_bootstrap(history, view, defaults, authority, policy)?;
            }
            (Some(selected), None) => {
                VerifiedRootScope::verify_with_recorded_properties(
                    history,
                    view,
                    defaults,
                    Some(selected),
                )?;
            }
            (Some(selected), Some((authority, policy))) => {
                VerifiedRootScope::verify_with_recorded_properties_and_bootstrap(
                    history,
                    view,
                    defaults,
                    Some(selected),
                    authority,
                    policy,
                )?;
            }
        }
        Ok(())
    }
}
