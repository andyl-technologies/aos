//! Side-effect-free validation of every original frame in a finite Capture prefix.

use super::*;

impl<S: ProviderStream> Connection<S> {
    // Checks future window bodies without reserving correlations or sending bytes.
    // The owning Capture prefix retains originals before installed callbacks run.
    pub(crate) fn preflight_original_capture_frame(
        &mut self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_authority()?;
        let limits = self.authority.limits();
        let maximum_frame = allowance(limits.frame_bytes.get())?;
        super::prepared::serialized_credit(original, maximum_frame)?;
        self.validate_body(original, false)?;
        let value =
            serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        canonical::parse_json_with_depth(&bytes, maximum_frame, allowance(limits.nesting.get())?)?;
        self.check_authority()
    }
}
