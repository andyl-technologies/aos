//! Restricts distinct seven-bank Blob publication to its actual selected actor.

use super::*;
use crate::protocol_snapshot::ProtocolCaptureCut;

impl<S: ProviderStream> Connection<S> {
    /// Checks the genuine selected18 host and its settled correlation boundary.
    ///
    /// # Errors
    /// Refuses another codec/endpoint, expired registration or pending frame.
    pub(crate) fn preflight_native_import18_upload_data(&self) -> Result<(), ProviderError> {
        self.native_import18_selection_data()?;
        self.guard.protocol_cut(ProtocolCaptureCut::HostSettled)
    }
}
