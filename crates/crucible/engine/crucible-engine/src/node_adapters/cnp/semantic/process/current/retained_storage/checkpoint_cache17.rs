//! Ties a borrowed completed cache to the same actual armed native read.
//!
//! No pointer, callback, archived DTO or private cache flag can construct this
//! read token. Its defining constructor has already acquired the original
//! process/registrar/kernel custody and its sticky terminal fence.

use super::*;

impl OriginalFreshQueryReadCall<'_> {
    /// Rechecks this token against the exact native read retained by Source.
    ///
    /// # Errors
    /// Refuses another Source read, a finished/revoked/busy-owner mismatch,
    /// changed registrar/kernel/executable association or scratch failure.
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_original_source_read17_data(
        &self,
        expected: &CnpSemanticSourceRead,
        scratch: &mut super::super::super::executable_guard::FreshCurrentScratch,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        if !std::ptr::eq(self.original, expected) {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        self.ensure_original_fresh_current_before_effect_data(scratch)
    }
}
