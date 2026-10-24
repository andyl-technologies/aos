//! Lends immutable constructed verification inside a current publication scope.
//!
//! Its caller already holds the complete original
//! Codec/Source/Host/SDK loan, whose terminal guards enclose the whole operation.
//! Older received-request context loans retain their existing predicates.

use super::*;

impl Attempt {
    /// Lends completed verification DATA under the same original current owners.
    ///
    /// This private view permits a subsequent SDK state transition; it supplies
    /// no received-request loan, Source funding or native phase permission.
    /// The enclosing public method returns only Copy DATA after terminal guards.
    ///
    /// # Errors
    /// Refuses incomplete/failed verification or foreign/stale original custody.
    pub(in super::super) fn constructed_publication_context_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        operands: &BootstrapAckOperands<'_>,
        pending: bool,
    ) -> Result<(&Context, &[u8; 32]), ProviderError> {
        if (!self.complete && !pending)
            || self.failed
            || !self.verified
            || self.step != Some(Step::Verify)
        {
            return Err(refused());
        }
        self.authenticate_alias(original)?;
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        original.authenticate_channel()?;
        operands.ensure_current_authority_data()?;
        Ok((
            self.context.as_ref().ok_or_else(refused)?,
            self.digest.as_ref().ok_or_else(refused)?,
        ))
    }
}
