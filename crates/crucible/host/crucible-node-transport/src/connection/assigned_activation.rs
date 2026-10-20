//! Reserves and publishes only a selected, once-assigned activation original.

use super::*;
use crate::reference_packet::service::complete_restore::activation::*;
use crate::transport::original_frames::FrameDirection;
use serde_json::Value;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn reserve_original_assigned_installed_restoration_activation(
        &mut self,
        original: &Envelope,
        maximum: usize,
        result: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        let codec = self.native5_codec.as_ref().ok_or_else(refused)?;
        let selection = codec.fresh_restore_controller_selection_data(&self.authority)?;
        authenticate_restoration_activation_selection_data(selection, &self.authority)?;
        if self.role != EndpointRole::Controller
            || result.is_some()
            || original.message != MessageKind::Request
            || !matches!(original.method, Method::Activate | Method::WorldActivate)
            || maximum > allowance(self.authority.limits().frame_bytes.get())?
        {
            return Err(refused());
        }
        let phase = match original.method {
            Method::Activate => PacketRestorationActivationPhase::Arm,
            Method::WorldActivate => PacketRestorationActivationPhase::WorldActivate,
            _ => return Err(refused()),
        };
        restoration_activation_assigned_request_digest(original, phase, maximum)?;
        let extension = original
            .extensions
            .get(PACKET_RESTORATION_ACTIVATION_FEATURE)
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        if extension.len() != 1 {
            return Err(refused());
        }
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let mut bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        if !bank.complete() || bank.contains_original_id(id.as_str()) {
            return Err(refused());
        }
        let slot = bank.begin(
            FrameDirection::Outgoing,
            maximum.checked_add(4).ok_or_else(refused)?,
        )?;
        *result = Some(slot);
        bank.retain_request(slot, id)
    }

    pub(crate) fn publish_original_assigned_installed_restoration_activation(
        &mut self,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(refused());
        }
        self.validate_body(original, false)?;
        let result = self.publish_original_send(bytes, slot);
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        }
        result
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("assigned installed restoration activation changed")
}
