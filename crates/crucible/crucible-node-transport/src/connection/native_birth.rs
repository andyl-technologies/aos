//! Reads a baseline original only under the same real boot6/Control scope.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn authenticate_original_native_birth_policy_data(
        &self,
        actual: &Rc<crate::reference_packet::Native5Policy>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        match self.native5_codec.as_deref() {
            Some(Native5CodecOwner::NativePacket(installed)) if Rc::ptr_eq(installed, actual) => {
                Ok(())
            }
            _ => Err(ProviderError::Correlation(
                "native birth actual policy differs",
            )),
        }
    }

    pub(crate) fn receive_original_native_birth_request(
        &mut self,
        scope: &OriginalNativeBirthReadScope<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        scope.authenticate_connection(self)?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation("native birth request direction"));
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_native_birth_request_inner(scope);
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_native_birth_request_inner(
        &mut self,
        scope: &OriginalNativeBirthReadScope<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        scope.authenticate_body_data(
            value
                .get("body")
                .ok_or(ProviderError::Frame("native birth body absent"))?,
        )?;
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        scope.authenticate_header_data(self, &envelope)?;
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        scope.authenticate_connection(self)?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }
}
