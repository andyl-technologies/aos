//! Checks compatibility associations against installed authenticated history.
//!
//! Borrowed configuration never replaces a view's exact independent selection.

use super::{
    Defaults, Digest, OriginalBootstrapPolicy, Rejected, VerifiedHistory, VerifiedRootScope,
};
use crate::properties::{selected::Selection, semantics::associations::RecordedAssociation};

impl VerifiedRootScope {
    /// Verifies original scope under the already installed exact recorded selection.
    ///
    /// # Errors
    /// Rejects absent or mismatched association and every original scope failure.
    pub fn verify_with_recorded_properties(
        history: &mut VerifiedHistory,
        view: Digest,
        defaults: Defaults<'_>,
        association: Option<&RecordedAssociation>,
    ) -> Result<Self, Rejected> {
        check(history, view, association)?;
        super::verify_root_context(history, view, defaults)
    }

    /// Verifies exact recorded original scope with independent bootstrap evidence.
    ///
    /// # Errors
    /// Rejects selection mismatch and original signature, scope or bootstrap failures.
    pub fn verify_with_recorded_properties_and_bootstrap(
        history: &mut VerifiedHistory,
        view: Digest,
        defaults: Defaults<'_>,
        association: Option<&RecordedAssociation>,
        expected_original_authority: &str,
        policy: OriginalBootstrapPolicy<'_>,
    ) -> Result<Self, Rejected> {
        check(history, view, association)?;
        super::verify_root_context_with_bootstrap(
            history,
            view,
            defaults,
            expected_original_authority,
            policy,
        )
    }

    /// Compares exact independently installed selection against checked scope data.
    pub(in crate::provenance) fn matches_selection(&self, selection: &Selection) -> bool {
        &self.selection == selection
    }

    /// Compares retained exact configuration without conferring authority.
    pub(in crate::provenance) fn matches_properties(
        &self,
        association: Option<&RecordedAssociation>,
    ) -> bool {
        match (&self.selection, association) {
            (Selection::Recorded(context), Some(selected)) => {
                self.view == selected.view()
                    && self.plan.candidate == selected.original_root()
                    && context == selected.context()
            }
            (Selection::Legacy | Selection::Active, None) => true,
            _ => false,
        }
    }
}

fn check(
    history: &VerifiedHistory,
    view: Digest,
    association: Option<&RecordedAssociation>,
) -> Result<(), Rejected> {
    let selected = association.ok_or(Rejected)?;
    let root = history.commit(&view).ok_or(Rejected)?.commit().tree;
    if selected.view() != view
        || selected.original_root() != root
        || history.view_selection(view)? != Selection::Recorded(selected.context().clone())
    {
        return Err(Rejected);
    }
    Ok(())
}
