//! Fences first-Observe receiver quotation at an actual idle correlation cut.

use super::*;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn ensure_original_observation_receiver_idle_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authority.ensure_live()?;
        if self.role != EndpointRole::Controller || self.fenced {
            return Err(ProviderError::Correlation(
                "first Observe receiver is not the same idle Controller",
            ));
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
    }
}
