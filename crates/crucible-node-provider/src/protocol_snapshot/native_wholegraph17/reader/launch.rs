//! Compares the real Source-owned decoded launch with exact native launch bytes.

use super::*;
use crate::connection::native17_borrowed_bytes::{Bytes17, ExactBytes17, field};
use crate::reference_packet::service::PacketNative5SourceLaunch;

impl NativeCurrentGraph17Data {
    /// Checks the complete original raw5 launch against a genuine Source DTO.
    ///
    /// The Source caller independently funds the bounded temporary JSON value
    /// before calling. This comparison creates no native identity, source
    /// ancestry, signer or runtime installation from the archived launch bytes.
    ///
    /// # Errors
    /// Refuses an oversized/invalid launch, malformed native byte bank or any
    /// canonical byte disagreement, including omitted optional launch fields.
    pub(crate) fn authenticate_original_launch_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        launch.validate()?;
        crate::connection::serialized_credit(launch, 1024 * 1024)?;
        let roots = self.raw_root_spans_data()?;
        let (bytes, _) = Bytes17::bank(field(roots.boot_data(), "launch")?, false)?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let value = serde_json::to_value(launch).map_err(|_| invalid())?;
        let mut sink = ExactBytes17::new(bytes)?;
        crucible_node_contract::canonical::canonical_json_to_writer(&value, &mut sink)?;
        sink.finish()
    }
}
