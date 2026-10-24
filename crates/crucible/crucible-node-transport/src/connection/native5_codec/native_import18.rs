//! Borrows the actual Controller policy under its defining negotiation guard.

use super::*;

impl ControllerNative5Policy {
    /// Borrows the real installation before separate full import18 checks.
    ///
    /// # Errors
    /// Refuses revoked registration or changed negotiated source features.
    pub(in crate::connection) fn original_native_import18_selection_data(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<&PacketControlSelection, ProviderError> {
        self.validate_current_negotiation(authority)?;
        Ok(&self.selection)
    }
}
