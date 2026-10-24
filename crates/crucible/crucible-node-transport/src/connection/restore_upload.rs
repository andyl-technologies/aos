//! Restricts selected host input publication to its real installed codec.

use super::*;
use crate::{
    protocol_snapshot::ProtocolCaptureCut,
    reference_packet::service::complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
};

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn preflight_original_restore_upload_data(&self) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.original_native5_restore_input_emitter_selection()?
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        {
            return Err(ProviderError::Correlation(
                "original uploader selection differs",
            ));
        }
        self.guard.protocol_cut(ProtocolCaptureCut::HostSettled)
    }
}
