//! Factual observation of an original block response at its registered inbox.
//!
//! Observations retain the exact physical frame and consumer frontier. They
//! must be rechecked with the original live request token before use and confer
//! no permission to deliver, dequeue, or issue a fixed-input acceptance.

use super::*;

/// Factual custody of an original block response before guest delivery.
///
/// The process-local observation binds the request's callback owner, epoch and
/// request ID to the registered mapped ring generation and exact physical head.
/// It carries no fixed-input Source or Host actor authority.
#[derive(Clone, Debug)]
pub struct BlockInboundHead {
    owner_id: u64,
    device_owner_id: u64,
    device_request_seq: u64,
    identity: BlockRequestIdentity,
    ring_index: u32,
    ring_generation: u64,
    read_index: u64,
    frame: FrameEntry,
}

impl BlockInboundHead {
    /// Returns the original request's epoch-scoped wire identity.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        self.identity
    }

    /// Returns the registration-fixed directed inbox index.
    #[must_use]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    /// Returns the generation issued when the mapped ring owner was installed.
    #[must_use]
    pub const fn ring_generation(&self) -> u64 {
        self.ring_generation
    }

    /// Returns the original absolute consumer frontier.
    #[must_use]
    pub const fn read_index(&self) -> u64 {
        self.read_index
    }

    /// Returns the original physical response key.
    #[must_use]
    pub fn delivery_key(&self) -> FrameDeliveryKey {
        self.frame.delivery_key()
    }
}

impl PluginBlockIo {
    /// Observes the registered physical response for an original pending request.
    ///
    /// The caller retains the original request token in the live callback map.
    /// A foreign owner, unregistered ring, staged delivery, transport event, or
    /// different request at the head returns `None`. Delivery time alone does
    /// not identify a response and this observation does not consume it.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] for a wrong ring, malformed response, or invalid
    /// original device-I/O token.
    pub fn observe_inbound_head(
        &self,
        freeze: &PluginDeviceIoFreeze,
        inbound_ring: &BlockInboundRing<'_>,
        token: &BlockRequestToken,
    ) -> Result<Option<BlockInboundHead>, BlockIoError> {
        self.check_inbound_ring(inbound_ring)?;
        if inbound_ring.registered_generation() == 0
            || token.block_owner_id != self.owner_id
            || self.pending_delivery.borrow().is_some()
        {
            return Ok(None);
        }
        freeze
            .completion_current(
                &token.device_token,
                crate::DeviceIoRequestOutcome::Completed,
            )
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;

        let read_index = inbound_ring.header.read_index();
        let head = peek_head_frame(inbound_ring)?;
        if inbound_ring.header.read_index() != read_index {
            return Ok(None);
        }
        let Some(frame) = head else {
            return Ok(None);
        };
        if frame.src_node != self.block_slot || frame.seq != token.identity.request_id() {
            return Ok(None);
        }
        let payload = frame
            .payload()
            .map_err(|source| BlockIoError::Frame { source })?;
        let response = BlockResponse::decode(payload)?;
        if response.identity() != token.identity
            || matches!(
                response.status(),
                BlockResponseStatus::TransportReset
                    | BlockResponseStatus::DuplicateIgnored
                    | BlockResponseStatus::DuplicateProtocolError
            )
        {
            return Ok(None);
        }

        Ok(Some(BlockInboundHead {
            owner_id: self.owner_id,
            device_owner_id: token.device_token.owner_id(),
            device_request_seq: token.device_token.request_seq(),
            identity: token.identity,
            ring_index: self.inbound_ring_index,
            ring_generation: inbound_ring.registered_generation(),
            read_index,
            frame,
        }))
    }

    /// Rechecks the same actual head and original pending request before use.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] for a wrong ring, malformed response, or invalid
    /// original device-I/O token. A changed, consumed, or remapped head returns
    /// `false`.
    pub fn inbound_head_current(
        &self,
        freeze: &PluginDeviceIoFreeze,
        inbound_ring: &BlockInboundRing<'_>,
        token: &BlockRequestToken,
        observed: &BlockInboundHead,
    ) -> Result<bool, BlockIoError> {
        if observed.owner_id != self.owner_id
            || observed.device_owner_id != token.device_token.owner_id()
            || observed.device_request_seq != token.device_token.request_seq()
            || observed.identity != token.identity
            || observed.ring_index != self.inbound_ring_index
            || observed.ring_generation != inbound_ring.registered_generation()
            || inbound_ring.header.read_index() != observed.read_index
        {
            return Ok(false);
        }
        let current = self.observe_inbound_head(freeze, inbound_ring, token)?;
        Ok(current.is_some_and(|current| {
            current.read_index == observed.read_index
                && same_response_frame(&current.frame, &observed.frame)
        }))
    }
}
