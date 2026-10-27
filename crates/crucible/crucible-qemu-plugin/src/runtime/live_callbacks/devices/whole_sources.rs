//! Short guarded observations of original block and read-only 9p token owners.
//!
//! Lookups borrow tokens created by successful original submit callbacks. Public
//! identities select a retained token but never construct one. No native call or
//! queue effect occurs while the device mutex is held.

use crucible_qemu_protocol::whole_control::inventory::{WholeQueueRecord, WholeQueueRole};

use super::LiveDeviceCallbackState;
use crate::runtime::live_callbacks::{
    StableDirectedRingHandle,
    whole_sources::{EndpointObservation, NativeSourceObservation, SourceResult, WholeSourceError},
};
use crate::{BlockRequestIdentity, BlockResponse, BlockResponseStatus, NinePWireMessage};

impl LiveDeviceCallbackState {
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(in crate::runtime::live_callbacks) fn initialize_whole_reservations(
        &mut self,
        capacity: usize,
        byte_limit: u64,
    ) -> SourceResult<()> {
        self.whole_reservations.initialize(capacity, byte_limit)
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(in crate::runtime::live_callbacks) fn activate_whole_reservations(
        &mut self,
        original_source_matches: bool,
    ) -> SourceResult<()> {
        self.whole_reservations.activate(original_source_matches)
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(in crate::runtime::live_callbacks) fn whole_reservation_storage_bytes(
        &self,
    ) -> SourceResult<u64> {
        self.whole_reservations.storage_bytes()
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(in crate::runtime::live_callbacks) fn reserve_whole_original_token(
        &mut self,
        observation: &NativeSourceObservation,
        record: &WholeQueueRecord<'_>,
        stage_allocation: usize,
        record_index: u32,
    ) -> SourceResult<()> {
        let response_capacity = self
            .validate_whole_pending(record.role, observation, record)?
            .ok_or(WholeSourceError::Mismatch("original input completion role"))?;
        let family = match record.role {
            WholeQueueRole::BlockCompletion => {
                super::token_reservations::OriginalRequestFamily::Block
            }
            WholeQueueRole::ReadonlyNinePCompletion => {
                super::token_reservations::OriginalRequestFamily::ReadonlyNineP
            }
            _ => {
                return Err(WholeSourceError::Mismatch(
                    "original device reservation role",
                ));
            }
        };
        self.whole_reservations.reserve(
            super::token_reservations::OriginalRequestKey {
                family,
                epoch: record.transport_epoch,
                id: u32::try_from(record.native_id)
                    .map_err(|_| WholeSourceError::Mismatch("original request width"))?,
            },
            stage_allocation,
            record_index,
            response_capacity,
        )
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(in crate::runtime::live_callbacks) fn whole_source_ring(
        &self,
        role: WholeQueueRole,
        block: &EndpointObservation,
        ninep: &EndpointObservation,
    ) -> SourceResult<(&StableDirectedRingHandle, u64, u64)> {
        match role {
            WholeQueueRole::BlockCompletion | WholeQueueRole::BlockRequest => {
                if block.identity.present != 1
                    || block.epoch != self.block.request_epoch()
                    || block.next_id != u64::from(self.block.next_request_id())
                    || self.pending_block_event.is_some()
                {
                    return Err(WholeSourceError::Mismatch(
                        "actual block transport frontier",
                    ));
                }
                Ok((
                    if role.is_input() {
                        &self.block_rings.inbound
                    } else {
                        &self.block_rings.outbound
                    },
                    block.epoch,
                    block.next_id,
                ))
            }
            WholeQueueRole::ReadonlyNinePCompletion | WholeQueueRole::ReadonlyNinePRequest => {
                if ninep.identity.present != 1
                    || ninep.epoch != 0
                    || ninep.next_id != u64::from(self.ninep.next_request_id())
                {
                    return Err(WholeSourceError::Mismatch("actual read-only 9p frontier"));
                }
                Ok((
                    if role.is_input() {
                        &self.ninep_rings.inbound
                    } else {
                        &self.ninep_rings.outbound
                    },
                    0,
                    ninep.next_id,
                ))
            }
            _ => Err(WholeSourceError::Mismatch("actual device role")),
        }
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(in crate::runtime::live_callbacks) fn validate_whole_pending(
        &self,
        role: WholeQueueRole,
        observation: &NativeSourceObservation,
        record: &WholeQueueRecord<'_>,
    ) -> SourceResult<Option<usize>> {
        match role {
            WholeQueueRole::BlockCompletion => {
                let native = &observation.block;
                let id = u32::try_from(record.native_id)
                    .map_err(|_| WholeSourceError::Mismatch("block request width"))?;
                let identity = BlockRequestIdentity::new(record.transport_epoch, id);
                let token = self
                    .block_tokens
                    .get(&identity)
                    .ok_or(WholeSourceError::Mismatch("original pending block token"))?;
                let response = BlockResponse::decode(record.payload)
                    .map_err(|_| WholeSourceError::Mismatch("complete block response"))?;
                if token.identity() != identity
                    || !self
                        .block
                        .original_completion_token_current(&self.freeze, token)
                    || native.pending != 0
                    || native.pending_id != 0
                    || native.response_capacity != 0
                    || response.identity() != identity
                    || !token.original_response_shape_current(&response)
                    || native.epoch != identity.epoch()
                    || self.block.pending_delivery_len(identity).is_some()
                    || matches!(
                        response.status(),
                        BlockResponseStatus::TransportReset
                            | BlockResponseStatus::DuplicateIgnored
                            | BlockResponseStatus::DuplicateProtocolError
                    )
                    || self.block_reissue_preserve.contains(&identity)
                {
                    return Err(WholeSourceError::Mismatch(
                        "current original block completion",
                    ));
                }
                return Ok(Some(token.original_response_capacity()));
            }
            WholeQueueRole::ReadonlyNinePCompletion => {
                let native = &observation.ninep;
                let id = u32::try_from(record.native_id)
                    .map_err(|_| WholeSourceError::Mismatch("9p request width"))?;
                let pending = self
                    .ninep_tokens
                    .get(&id)
                    .ok_or(WholeSourceError::Mismatch("original pending 9p token"))?;
                NinePWireMessage::decode(record.payload)
                    .map_err(|_| WholeSourceError::Mismatch("complete 9p reply"))?;
                if pending.token.request_id() != id
                    || !self
                        .ninep
                        .original_completion_token_current(&self.freeze, &pending.token)
                    || native.pending == 0
                    || native.pending_id != record.native_id
                    || record.frame_sequence != id
                    || native.epoch != 0
                    || record.transport_epoch != 0
                    || native.response_capacity != pending.response_capacity as u64
                    || record.payload.len() > pending.response_capacity
                    || self.ninep.pending_delivery_len(id).is_some()
                {
                    return Err(WholeSourceError::Mismatch(
                        "current original read-only 9p completion",
                    ));
                }
                return Ok(Some(pending.response_capacity));
            }
            WholeQueueRole::BlockRequest | WholeQueueRole::ReadonlyNinePRequest => {}
            _ => return Err(WholeSourceError::Mismatch("actual pending device role")),
        }
        Ok(None)
    }
}
