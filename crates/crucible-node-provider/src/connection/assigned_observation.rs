//! Reserves and publishes only a selected, once-assigned observation original.

use super::*;
use crate::reference_packet::service::complete_restore::restoration_observe::*;
use crate::transport::original_frames::FrameDirection;
use serde_json::Value;

impl<S: ProviderStream> Connection<S> {
    /// Names the original-bank mutable loan before reserved-slot construction.
    pub(crate) const fn original_assigned_installed_restoration_observation_counter_scratch_data()
    -> usize {
        use crate::transport::original_frames::OriginalFrameReservation;
        use std::{
            cell::{BorrowMutError, RefMut},
            mem::size_of,
        };
        size_of::<RefMut<'static, OriginalFrameReservation>>()
            + size_of::<Result<RefMut<'static, OriginalFrameReservation>, BorrowMutError>>()
            + size_of::<Result<RefMut<'static, OriginalFrameReservation>, ProviderError>>()
    }

    pub(crate) fn reserve_original_assigned_installed_restoration_observation(
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
        authenticate_restoration_observe_selection_data(selection, &self.authority)?;
        if self.role != EndpointRole::Controller
            || result.is_some()
            || original.message != MessageKind::Request
            || original.method != Method::Observe
            || maximum > allowance(self.authority.limits().frame_bytes.get())?
        {
            return Err(refused());
        }
        restoration_observe_assigned_request_digest(original, maximum)?;
        let extension = original
            .extensions
            .get(PACKET_RESTORATION_OBSERVE_FEATURE)
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

    pub(crate) fn publish_original_assigned_installed_restoration_observation(
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
    ProviderError::Correlation("assigned installed restoration observation changed")
}
