//! Reserves and publishes only the exact assigned complete-restoration original.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{
    PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING, PacketNative5FreshRestoreAllocationSelection,
};

use crate::reference_packet::service::complete_restore::*;
use crate::transport::original_frames::FrameDirection;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn reserve_original_assigned_complete_restore(
        &mut self,
        original: &Envelope,
        maximum: usize,
        result: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller
            || result.is_some()
            || original.message != MessageKind::Request
            || original.method != Method::Begin
            || original.extensions.len() != 1
            || !original
                .extensions
                .contains_key(PACKET_COMPLETE_RESTORE_FEATURE)
            || original
                .body
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("prepare_restore")
        {
            return Err(ProviderError::Correlation(
                "assigned complete restore reservation scope",
            ));
        }
        let maximum_frame = allowance(self.authority.limits().frame_bytes.get())?;
        if maximum > maximum_frame {
            return Err(ProviderError::ResourceExhausted(
                "assigned restore frame allowance",
            ));
        }
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned restore ID absent"))?;
        let mut bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned restore bank absent"))?
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("assigned restore bank borrowed"))?;
        if !bank.complete() || bank.contains_original_id(id.as_str()) {
            return Err(ProviderError::Conflict(
                "assigned restore original history changed",
            ));
        }
        let slot = bank.begin(
            FrameDirection::Outgoing,
            maximum
                .checked_add(4)
                .ok_or(ProviderError::ResourceExhausted(
                    "assigned restore framed extent",
                ))?,
        )?;
        *result = Some(slot);
        bank.retain_request(slot, id)
    }

    pub(crate) fn publish_original_assigned_complete_restore(
        &mut self,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        CompleteRestoreProjection::from_envelope(original)?;
        if original.message != MessageKind::Request {
            return Err(ProviderError::Correlation(
                "assigned restore publication scope",
            ));
        }
        let result = self.publish_original_send(bytes, slot);
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        }
        result
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn reserve_original_assigned_complete_restore_transfer(
        &mut self,
        original: &Envelope,
        maximum: usize,
        result: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::service::complete_restore::{
            PacketNative5CompleteRestoreSelection, transfer::PacketCompleteRestoreTransferPhase,
        };
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let fresh_binding = original
            .extensions
            .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
        if fresh_binding {
            if self
                .native5_codec
                .as_ref()
                .ok_or(ProviderError::Correlation("assigned fresh codec absent"))?
                .fresh_restore_selection_data(&self.authority)?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            {
                return Err(ProviderError::Correlation(
                    "assigned fresh Prepare selection absent",
                ));
            }
            transfer::authenticate_fresh_prepare_shape(original, false)?;
        }
        if self.role != EndpointRole::Controller
            || result.is_some()
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || original.message != MessageKind::Request
            || original.method != Method::Begin
            || (!fresh_binding && original.extensions.len() != 1)
            || ![
                PacketCompleteRestoreTransferPhase::Prepare,
                PacketCompleteRestoreTransferPhase::Commit,
            ]
            .into_iter()
            .any(|phase| original.extensions.contains_key(phase.request_extension()))
            || original
                .body
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("prepare_restore")
        {
            return Err(ProviderError::Correlation(
                "assigned restore transfer reservation scope",
            ));
        }
        if maximum > allowance(self.authority.limits().frame_bytes.get())? {
            return Err(ProviderError::ResourceExhausted(
                "assigned restore transfer frame allowance",
            ));
        }
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned transfer ID absent"))?;
        let mut bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned transfer bank absent"))?
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("assigned transfer bank borrowed"))?;
        if !bank.complete() || bank.contains_original_id(id.as_str()) {
            return Err(ProviderError::Conflict(
                "assigned transfer original history changed",
            ));
        }
        let slot = bank.begin(
            FrameDirection::Outgoing,
            maximum
                .checked_add(4)
                .ok_or(ProviderError::ResourceExhausted(
                    "assigned transfer framed extent",
                ))?,
        )?;
        *result = Some(slot);
        bank.retain_request(slot, id)
    }

    pub(crate) fn publish_original_assigned_complete_restore_transfer(
        &mut self,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller
            || !matches!(
                self.original_selected_restore_transfer_projection_data(original)?,
                CompleteRestoreTransferProjection::Request { .. }
            )
        {
            return Err(ProviderError::Correlation(
                "assigned restore transfer publication scope",
            ));
        }
        let result = self.publish_original_send(bytes, slot);
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        }
        result
    }
}
