//! Retains ordinary per-view interpretation inputs without granting authority.
//!
//! The explicit mode and complete registry distinguish coincident policy results.
//! Property revisions require exact spec-registered vocabularies. Unsupported
//! non-property semantic uints remain ordinary data until a support check.
//! Absence in a used-input record never
//! means Legacy. Current selection, signed roots, original trust and completed
//! producer evidence remain independent owning obligations.
//!
//! ```text
//! consumed-view-interpretation = [view32, original_namespace_root32,
//!                                legacy_0_or_recorded_1, registry_inputs]
//! ```

use super::validation::Validate;
use super::{ConfiguredRegistryInputs, EvidenceError, RawDigest};

/// Identifies an explicitly recorded property-interpretation selection mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewInterpretationMode {
    /// Records the actual registered Legacy inputs, never an absent mapping.
    Legacy,
    /// Records an independently selected association, including current revisions.
    Recorded,
}

/// Carries the ordinary interpretation claim for one actually consumed view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedViewInterpretation {
    /// Domain-separated signed view commit identity.
    pub view: RawDigest,
    /// Original signed namespace root before any fold filtering.
    pub original_root: RawDigest,
    /// Explicit Legacy or Recorded selection made by the actual producer.
    pub mode: ViewInterpretationMode,
    /// Complete actual per-view property fence and registered semantic inputs.
    pub registries: ConfiguredRegistryInputs,
}

impl ConsumedViewInterpretation {
    /// Compares two complete ordinary selections without authenticating either.
    ///
    /// A native caller must independently obtain the current selection, signed
    /// root and producer evidence. Neither argument creates those capabilities.
    /// Unrelated association-table entries are not part of this comparison.
    ///
    /// # Errors
    /// Rejects malformed name fences, unregistered property revisions, or any
    /// differing view, original root, mode,
    /// revision, name set or other semantic input.
    pub fn check_selected_data(&self, selected: &Self) -> Result<(), EvidenceError> {
        self.validate()?;
        selected.validate()?;
        if self != selected {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }

    /// Checks the represented signed-view identity and original namespace root.
    ///
    /// This checks ordinary Commit data, including signature presence only.
    /// Signature validity, embedded token, original history and current request
    /// authority remain independent; a signed-looking record creates none.
    /// The supplied view must be the original Commit before fold filtering.
    ///
    /// # Errors
    /// Rejects malformed context data, unregistered property revisions, missing
    /// signatures, unidentified Commit
    /// data, or a mismatched signed-view identity or original root.
    pub fn check_signed_view_data(
        &self,
        commit: &crate::refs::Commit,
    ) -> Result<(), EvidenceError> {
        self.validate()?;
        if commit.signature.is_none()
            || commit.identity()? != self.view
            || commit.tree != self.original_root
        {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }

    /// Checks whether this ordinary claim uses supported registered semantics.
    ///
    /// This checks data only; it supplies neither current authority nor complete
    /// signed-history, index relationship or cold-source producer evidence.
    ///
    /// # Errors
    /// Rejects malformed fences, unsupported semantic revisions or identity
    /// profiles, and names differing from a supported registered vocabulary.
    pub fn check_supported_interpretation(&self) -> Result<(), EvidenceError> {
        self.validate()?;
        self.registries.validate()
    }
}
