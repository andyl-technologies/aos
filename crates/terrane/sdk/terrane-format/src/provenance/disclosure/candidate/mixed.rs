//! Stages genuine disclosure validation with exact mixed property selections.
//!
//! Interpretation inputs remain ordinary configuration. Certificate, signed
//! history, every dependency's original scope and independent bootstrap checks
//! still belong to the existing complete candidate verifier.

use super::{DisclosureAuthority, DisclosureCandidate, Interpretation};
use crate::identity::Digest;
use crate::properties::{Defaults, semantics::selections::ViewPropertySelections};
use crate::provenance::{OriginalBootstrapPolicy, Rejected, VerifiedHistory};

impl<'a> DisclosureCandidate<'a> {
    /// Authenticates certificates using each view's independently selected properties.
    ///
    /// The immutable selection is copied. Legacy ancestors retain Legacy while
    /// Recorded views keep their exact original-root fence and inert later names.
    /// These inputs authenticate no association or registration. Only successful
    /// [`Self::finish`] exposes history after complete origin and scope checks.
    /// Initial or certified-fresh views still require independently trusted
    /// bootstrap input through [`Self::new_with_property_selections_and_bootstrap`].
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing or mismatched view/root selections,
    /// conflicting retained scopes, or any certificate, canonical witness,
    /// original-context or origin failure of [`Self::new`].
    pub fn new_with_property_selections(
        history: &VerifiedHistory,
        view: Digest,
        authorities: &[DisclosureAuthority<'_>],
        defaults: Defaults<'a>,
        selections: &ViewPropertySelections,
    ) -> Result<Self, Rejected> {
        Self::stage(
            history,
            view,
            authorities,
            defaults,
            Interpretation::Mixed(selections.clone()),
        )
    }

    /// Stages mixed validation with separately trusted original bootstrap evidence.
    ///
    /// Original authority/ref/epoch and ACL evidence remain independent of the
    /// property selection. No checked history or boundary is exposed before
    /// [`Self::finish`] completes every retained public dependency and origin.
    ///
    /// # Errors
    /// Returns [`Rejected`] for invalid original authority/ref/epoch bootstrap
    /// inputs and every failure of [`Self::new_with_property_selections`].
    pub fn new_with_property_selections_and_bootstrap(
        history: &VerifiedHistory,
        view: Digest,
        authorities: &[DisclosureAuthority<'_>],
        defaults: Defaults<'a>,
        selections: &ViewPropertySelections,
        expected_original_authority: &'a str,
        policy: OriginalBootstrapPolicy<'a>,
    ) -> Result<Self, Rejected> {
        policy.check(
            history.commit(&view).ok_or(Rejected)?,
            expected_original_authority,
        )?;
        let mut candidate =
            Self::new_with_property_selections(history, view, authorities, defaults, selections)?;
        candidate.bootstrap = Some((expected_original_authority, policy));
        Ok(candidate)
    }
}
