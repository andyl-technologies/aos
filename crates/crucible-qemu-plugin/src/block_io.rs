//! Block-device submit and poll callback core.
//!
//! The block callbacks route guest requests through the deterministic block
//! executor slot. Submit encodes the versioned block wire request into the
//! `(vm_slot -> SLOT_BLK_IO)` SPSC ring and starts the device-I/O time hold. Poll
//! peeks the `(SLOT_BLK_IO -> vm_slot)` ring, exposes a response only after its
//! delivery icount has been reached, and consumes the matching freeze token.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crucible_shmem::{
    DirectedRing, FrameDeliveryKey, FrameEntry, FrameEntryError, MAX_FRAME_DATA, NodeSlot,
    RingHeader, SLOT_BLK_IO, SpscRingError,
};

use crate::{
    DeviceIoFreezeError, DeviceIoRequestRelease, DeviceIoRequestToken, PluginDeviceIoFreeze,
    PluginStorageHistoryLimits, shmem_ordering::PluginShmemOrdering,
};

mod completion;
mod errors;
mod history;
mod wire;

pub use completion::*;
pub use errors::*;
pub use wire::*;

use history::{CompletedEpochHistory, CompletedIdentityHistory, reserve_history};

const BLOCK_IO_SLOT_U32: u32 = SLOT_BLK_IO as u32;
const BLOCK_WIRE_VERSION: u8 = 4;
const BLOCK_REQUEST_HEADER_LEN: usize = 28;
const BLOCK_RESPONSE_HEADER_LEN: usize = 20;
const BLOCK_TRANSPORT_CONTINUATION_MAGIC: &[u8; 4] = b"CBTS";
const BLOCK_TRANSPORT_CONTINUATION_VERSION: u16 = 1;
const BLOCK_TRANSPORT_CONTINUATION_HEADER_LEN: usize = 28;
const BLOCK_TRANSPORT_CONTINUATION_EPOCH_LEN: usize = 24;

/// Epoch-scoped identity of one request on the block transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockRequestIdentity {
    epoch: u64,
    request_id: u32,
}

impl BlockRequestIdentity {
    /// Creates an identity from its transport epoch and epoch-local ID.
    pub const fn new(epoch: u64, request_id: u32) -> Self {
        Self { epoch, request_id }
    }

    /// Returns the transport generation.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the correlation ID within the generation.
    #[must_use]
    pub const fn request_id(self) -> u32 {
        self.request_id
    }
}

/// Registration-time-fixed block callback state.
#[derive(Debug)]
pub struct PluginBlockIo {
    vm_slot: u32,
    block_slot: u32,
    outbound_ring_index: u32,
    inbound_ring_index: u32,
    request_epoch: Cell<u64>,
    next_request_id: Cell<u32>,
    completed_history_limits: PluginStorageHistoryLimits,
    completed_identities: RefCell<CompletedIdentityHistory>,
}

impl PluginBlockIo {
    /// Builds block callback state from the directed rings selected at registration.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError::WrongOutboundRing`] or
    /// [`BlockIoError::WrongInboundRing`] when either ring is not the reserved
    /// block executor ring for `vm_slot`.
    #[cfg(test)]
    pub(crate) fn from_directed_rings(
        vm_slot: u32,
        outbound_ring: DirectedRing,
        inbound_ring: DirectedRing,
    ) -> Result<Self, BlockIoError> {
        Self::from_directed_rings_with_history_limits(
            vm_slot,
            outbound_ring,
            inbound_ring,
            PluginStorageHistoryLimits::compiled_maximum(),
        )
    }

    /// Builds block callback state with explicit authored history limits.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError::WrongOutboundRing`] or
    /// [`BlockIoError::WrongInboundRing`] when either ring is not the reserved
    /// block executor ring for `vm_slot`.
    pub fn from_directed_rings_with_history_limits(
        vm_slot: u32,
        outbound_ring: DirectedRing,
        inbound_ring: DirectedRing,
        completed_history_limits: PluginStorageHistoryLimits,
    ) -> Result<Self, BlockIoError> {
        if outbound_ring.src_slot != vm_slot || outbound_ring.dst_slot != BLOCK_IO_SLOT_U32 {
            return Err(BlockIoError::WrongOutboundRing {
                expected_src_slot: vm_slot,
                expected_dst_slot: BLOCK_IO_SLOT_U32,
                expected_ring_index: None,
                actual_src_slot: outbound_ring.src_slot,
                actual_dst_slot: outbound_ring.dst_slot,
                actual_ring_index: outbound_ring.index,
            });
        }
        if inbound_ring.src_slot != BLOCK_IO_SLOT_U32 || inbound_ring.dst_slot != vm_slot {
            return Err(BlockIoError::WrongInboundRing {
                expected_src_slot: BLOCK_IO_SLOT_U32,
                expected_dst_slot: vm_slot,
                expected_ring_index: None,
                actual_src_slot: inbound_ring.src_slot,
                actual_dst_slot: inbound_ring.dst_slot,
                actual_ring_index: inbound_ring.index,
            });
        }

        Ok(Self::new_with_history_limits(
            vm_slot,
            outbound_ring.index,
            inbound_ring.index,
            completed_history_limits,
        ))
    }

    /// Builds block callback state for the reserved block rings.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn new(
        vm_slot: u32,
        outbound_ring_index: u32,
        inbound_ring_index: u32,
    ) -> Self {
        Self::new_with_history_limits(
            vm_slot,
            outbound_ring_index,
            inbound_ring_index,
            PluginStorageHistoryLimits::compiled_maximum(),
        )
    }

    /// Builds block callback state with explicit authored history limits.
    #[must_use]
    pub const fn new_with_history_limits(
        vm_slot: u32,
        outbound_ring_index: u32,
        inbound_ring_index: u32,
        completed_history_limits: PluginStorageHistoryLimits,
    ) -> Self {
        Self {
            vm_slot,
            block_slot: BLOCK_IO_SLOT_U32,
            outbound_ring_index,
            inbound_ring_index,
            request_epoch: Cell::new(0),
            next_request_id: Cell::new(0),
            completed_history_limits,
            completed_identities: RefCell::new(CompletedIdentityHistory {
                epochs: BTreeMap::new(),
                gaps: 0,
            }),
        }
    }

    /// Returns the VM slot whose block device this state serves.
    #[must_use]
    pub const fn vm_slot(&self) -> u32 {
        self.vm_slot
    }

    /// Returns the reserved block executor slot.
    #[must_use]
    pub const fn block_slot(&self) -> u32 {
        self.block_slot
    }

    /// Returns the outbound block ring index.
    #[must_use]
    pub const fn outbound_ring_index(&self) -> u32 {
        self.outbound_ring_index
    }

    /// Returns the inbound block ring index.
    #[must_use]
    pub const fn inbound_ring_index(&self) -> u32 {
        self.inbound_ring_index
    }

    /// Returns the request id that the next successful submit will assign.
    #[must_use]
    pub fn next_request_id(&self) -> u32 {
        self.next_request_id.get()
    }

    /// Returns the epoch used by the next successful submit.
    #[must_use]
    pub fn request_epoch(&self) -> u64 {
        self.request_epoch.get()
    }

    /// Encodes the complete transport continuation for QEMU VMState.
    ///
    /// The closed little-endian format contains the allocator and the exact
    /// compact duplicate history. It contains no pointers or Rust-native enum
    /// layouts and is therefore safe to carry through the versioned process
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError::InvalidTransportContinuation`] if counts or the
    /// encoded length cannot be represented exactly.
    pub(crate) fn encode_transport_continuation(&self) -> Result<Vec<u8>, BlockIoError> {
        let history = self.completed_identities.borrow();
        let epoch_count = u32::try_from(history.epochs.len()).map_err(|_error| {
            BlockIoError::InvalidTransportContinuation {
                reason: "completed epoch count does not fit u32",
            }
        })?;
        let gap_count = u32::try_from(history.gaps).map_err(|_error| {
            BlockIoError::InvalidTransportContinuation {
                reason: "completed gap count does not fit u32",
            }
        })?;
        let epoch_bytes = history
            .epochs
            .len()
            .checked_mul(BLOCK_TRANSPORT_CONTINUATION_EPOCH_LEN)
            .ok_or(BlockIoError::InvalidTransportContinuation {
                reason: "completed epoch byte length overflow",
            })?;
        let gap_bytes = history
            .gaps
            .checked_mul(core::mem::size_of::<u32>())
            .ok_or(BlockIoError::InvalidTransportContinuation {
                reason: "completed gap byte length overflow",
            })?;
        let len = BLOCK_TRANSPORT_CONTINUATION_HEADER_LEN
            .checked_add(epoch_bytes)
            .and_then(|value| value.checked_add(gap_bytes))
            .ok_or(BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation length overflow",
            })?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(len).map_err(|_error| {
            BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation allocation failed",
            }
        })?;
        encoded.extend_from_slice(BLOCK_TRANSPORT_CONTINUATION_MAGIC);
        encoded.extend_from_slice(&BLOCK_TRANSPORT_CONTINUATION_VERSION.to_le_bytes());
        encoded.extend_from_slice(&0_u16.to_le_bytes());
        encoded.extend_from_slice(&self.request_epoch.get().to_le_bytes());
        encoded.extend_from_slice(&self.next_request_id.get().to_le_bytes());
        encoded.extend_from_slice(&epoch_count.to_le_bytes());
        encoded.extend_from_slice(&gap_count.to_le_bytes());
        for (epoch_id, epoch) in &history.epochs {
            let row_gaps = u32::try_from(epoch.out_of_order.len()).map_err(|_error| {
                BlockIoError::InvalidTransportContinuation {
                    reason: "completed epoch gap count does not fit u32",
                }
            })?;
            encoded.extend_from_slice(&epoch_id.to_le_bytes());
            encoded.extend_from_slice(&epoch.contiguous_exclusive.to_le_bytes());
            encoded.extend_from_slice(&row_gaps.to_le_bytes());
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            for request_id in &epoch.out_of_order {
                encoded.extend_from_slice(&request_id.to_le_bytes());
            }
        }
        if encoded.len() != len {
            return Err(BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation encoded length drifted",
            });
        }
        Ok(encoded)
    }

    /// Restores and validates a continuation paired with QEMU VMState.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError::InvalidTransportContinuation`] for every
    /// malformed, non-canonical, over-limit, truncated, or trailing-byte form.
    pub(crate) fn restore_transport_continuation(
        &self,
        encoded: &[u8],
        qemu_epoch: u64,
        qemu_next_request_id: u32,
    ) -> Result<(), BlockIoError> {
        if encoded.len() < BLOCK_TRANSPORT_CONTINUATION_HEADER_LEN
            || encoded.get(..4) != Some(BLOCK_TRANSPORT_CONTINUATION_MAGIC)
            || read_u16(encoded, 4) != Some(BLOCK_TRANSPORT_CONTINUATION_VERSION)
            || read_u16(encoded, 6) != Some(0)
        {
            return Err(BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation header is malformed",
            });
        }
        let epoch = read_u64(encoded, 8).ok_or(BlockIoError::InvalidTransportContinuation {
            reason: "transport continuation epoch is truncated",
        })?;
        let next_request_id =
            read_u32(encoded, 16).ok_or(BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation request id is truncated",
            })?;
        if epoch != qemu_epoch || next_request_id != qemu_next_request_id {
            return Err(BlockIoError::InvalidTransportContinuation {
                reason: "plugin allocator does not match paired QEMU VMState",
            });
        }
        let epoch_count = usize::try_from(read_u32(encoded, 20).ok_or(
            BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation epoch count is truncated",
            },
        )?)
        .map_err(|_error| BlockIoError::InvalidTransportContinuation {
            reason: "transport continuation epoch count does not fit usize",
        })?;
        let expected_gaps = usize::try_from(read_u32(encoded, 24).ok_or(
            BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation gap count is truncated",
            },
        )?)
        .map_err(|_error| BlockIoError::InvalidTransportContinuation {
            reason: "transport continuation gap count does not fit usize",
        })?;
        reserve_history(
            "storage_completed_history_epochs",
            0,
            u64::try_from(epoch_count).unwrap_or(u64::MAX),
            self.completed_history_limits.epochs(),
            crate::HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
        )?;
        reserve_history(
            "storage_completed_history_gaps",
            0,
            u64::try_from(expected_gaps).unwrap_or(u64::MAX),
            self.completed_history_limits.gaps(),
            crate::HARD_STORAGE_COMPLETED_HISTORY_GAPS,
        )?;
        let mut cursor = BLOCK_TRANSPORT_CONTINUATION_HEADER_LEN;
        let mut history = CompletedIdentityHistory::default();
        let mut previous_epoch = None;
        for _ in 0..epoch_count {
            let epoch_id =
                read_u64(encoded, cursor).ok_or(BlockIoError::InvalidTransportContinuation {
                    reason: "transport continuation epoch row is truncated",
                })?;
            let contiguous_exclusive = read_u64(encoded, cursor + 8).ok_or(
                BlockIoError::InvalidTransportContinuation {
                    reason: "transport continuation prefix is truncated",
                },
            )?;
            let row_gaps = usize::try_from(read_u32(encoded, cursor + 16).ok_or(
                BlockIoError::InvalidTransportContinuation {
                    reason: "transport continuation row gap count is truncated",
                },
            )?)
            .map_err(|_error| BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation row gap count does not fit usize",
            })?;
            if read_u32(encoded, cursor + 20) != Some(0)
                || previous_epoch.is_some_and(|previous| epoch_id <= previous)
                || contiguous_exclusive > u64::from(u32::MAX) + 1
                || (contiguous_exclusive == 0 && row_gaps == 0)
            {
                return Err(BlockIoError::InvalidTransportContinuation {
                    reason: "transport continuation epoch row is non-canonical",
                });
            }
            cursor = cursor
                .checked_add(BLOCK_TRANSPORT_CONTINUATION_EPOCH_LEN)
                .ok_or(BlockIoError::InvalidTransportContinuation {
                    reason: "transport continuation cursor overflow",
                })?;
            let mut out_of_order = BTreeSet::new();
            let mut previous_gap = None;
            for _ in 0..row_gaps {
                let request_id = read_u32(encoded, cursor).ok_or(
                    BlockIoError::InvalidTransportContinuation {
                        reason: "transport continuation gap is truncated",
                    },
                )?;
                if u64::from(request_id) < contiguous_exclusive
                    || previous_gap.is_some_and(|previous| request_id <= previous)
                {
                    return Err(BlockIoError::InvalidTransportContinuation {
                        reason: "transport continuation gap order is non-canonical",
                    });
                }
                out_of_order.insert(request_id);
                previous_gap = Some(request_id);
                cursor = cursor.checked_add(core::mem::size_of::<u32>()).ok_or(
                    BlockIoError::InvalidTransportContinuation {
                        reason: "transport continuation cursor overflow",
                    },
                )?;
            }
            history.gaps = history.gaps.checked_add(row_gaps).ok_or(
                BlockIoError::InvalidTransportContinuation {
                    reason: "transport continuation gap total overflow",
                },
            )?;
            history.epochs.insert(
                epoch_id,
                CompletedEpochHistory {
                    contiguous_exclusive,
                    out_of_order,
                },
            );
            previous_epoch = Some(epoch_id);
        }
        if cursor != encoded.len() || history.gaps != expected_gaps {
            return Err(BlockIoError::InvalidTransportContinuation {
                reason: "transport continuation length or gap total is inconsistent",
            });
        }
        self.request_epoch.set(epoch);
        self.next_request_id.set(next_request_id);
        *self.completed_identities.borrow_mut() = history;
        Ok(())
    }

    /// Submits one guest block request to the reserved block executor.
    ///
    /// The device-I/O hold is marked active before the frame is published to the
    /// SPSC ring. If enqueue fails, the request token is failed immediately so the
    /// pending counter cannot drift.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] when the ring does not match registration state,
    /// request encoding fails, the request id overflows, the device-I/O freeze
    /// state rejects the submit, or the outbound SPSC enqueue fails.
    pub fn submit_request(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        outbound_ring: &mut BlockOutboundRing<'_>,
        submit_icount: u64,
        request: &BlockRequest,
    ) -> Result<BlockSubmit, BlockIoError> {
        let identity =
            BlockRequestIdentity::new(self.request_epoch.get(), self.next_request_id.get());
        self.submit_request_as(
            freeze,
            slot,
            outbound_ring,
            submit_icount,
            request,
            identity,
            true,
        )
    }

    /// Submits a QEMU-authorized retry with an explicit transport identity.
    pub(crate) fn submit_retry_request(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        outbound_ring: &mut BlockOutboundRing<'_>,
        submit_icount: u64,
        request: &BlockRequest,
        identity: BlockRequestIdentity,
    ) -> Result<BlockSubmit, BlockIoError> {
        self.submit_request_as(
            freeze,
            slot,
            outbound_ring,
            submit_icount,
            request,
            identity,
            false,
        )
    }

    // crucible-lint: allow rust-allow -- the helper receives the complete fixed block request and shared-memory publication boundary.
    #[allow(clippy::too_many_arguments)]
    fn submit_request_as(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        outbound_ring: &mut BlockOutboundRing<'_>,
        submit_icount: u64,
        request: &BlockRequest,
        identity: BlockRequestIdentity,
        advance_allocator: bool,
    ) -> Result<BlockSubmit, BlockIoError> {
        self.check_outbound_ring(outbound_ring)?;
        let request_id = identity.request_id;
        let next_request_id = if advance_allocator {
            Some(
                request_id
                    .checked_add(1)
                    .ok_or(BlockIoError::RequestIdOverflow { request_id })?,
            )
        } else {
            None
        };
        let payload = request.encode(identity)?;
        let frame = FrameEntry::new(submit_icount, self.vm_slot, request_id, &payload)
            .map_err(|source| BlockIoError::Frame { source })?;
        let device_token = freeze
            .begin_independent_submit(slot, submit_icount)
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;

        if let Err(source) = PluginShmemOrdering::enqueue_outbound_frame(
            outbound_ring.header,
            outbound_ring.entries,
            &frame,
        ) {
            let release = freeze
                .fail_request(slot, device_token)
                .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;
            return Err(BlockIoError::RingEnqueueFailed {
                ring_index: self.outbound_ring_index,
                source,
                release,
            });
        }

        if let Some(next_request_id) = next_request_id {
            self.next_request_id.set(next_request_id);
        }
        Ok(BlockSubmit {
            ring_index: self.outbound_ring_index,
            submit_icount,
            request_id,
            payload_len: payload.len(),
            token: BlockRequestToken {
                identity,
                device_token,
            },
        })
    }

    /// Polls one block response and delivers it when its delivery icount is due.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] when the inbound ring does not match registration
    /// state, the response frame is malformed, a due response does not match the
    /// request token, the SPSC dequeue fails, delivery to QEMU fails, or the
    /// device-I/O token cannot be completed.
    pub fn poll_response<D>(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        inbound_ring: &BlockInboundRing<'_>,
        deliver: &mut D,
        current_icount: u64,
        token: BlockRequestToken,
    ) -> Result<BlockPoll, BlockIoError>
    where
        D: BlockGuestCompletion + ?Sized,
    {
        self.check_inbound_ring(inbound_ring)?;
        let Some(head) = peek_head_frame(inbound_ring)? else {
            return Ok(BlockPoll::NotReady { token });
        };
        if head.delivery_icount > current_icount {
            return Ok(BlockPoll::NotReady { token });
        }

        if head.src_node != self.block_slot {
            let release = self.fail_polled_request(freeze, slot, token)?;
            return Err(BlockIoError::UnexpectedSource {
                expected_src_node: self.block_slot,
                actual_src_node: head.src_node,
                frame: head.delivery_key(),
                release,
            });
        }

        let payload = match head.payload() {
            Ok(payload) => payload,
            Err(source) => {
                let release = self.fail_polled_request(freeze, slot, token)?;
                return Err(BlockIoError::MalformedResponse {
                    ring_index: self.inbound_ring_index,
                    frame: head.delivery_key(),
                    source: BlockWireError::FramePayload { source },
                    release,
                });
            }
        };
        let response = match BlockResponse::decode(payload) {
            Ok(response) => response,
            Err(source) => {
                let release = self.fail_polled_request(freeze, slot, token)?;
                return Err(BlockIoError::MalformedResponse {
                    ring_index: self.inbound_ring_index,
                    frame: head.delivery_key(),
                    source,
                    release,
                });
            }
        };
        if matches!(
            response.status(),
            BlockResponseStatus::TransportReset
                | BlockResponseStatus::DuplicateIgnored
                | BlockResponseStatus::DuplicateProtocolError
        ) {
            return Ok(BlockPoll::NotReady { token });
        }
        if response.identity() != token.identity {
            let expected_request_id = token.identity.request_id;
            let release = self.fail_polled_request(freeze, slot, token)?;
            return Err(BlockIoError::UnexpectedResponse {
                expected_request_id,
                actual_request_id: response.request_id(),
                frame: head.delivery_key(),
                release,
            });
        }
        self.completed_identities
            .borrow()
            .ensure_record_capacity(response.identity(), self.completed_history_limits)?;
        let release = freeze
            .complete_request(slot, token.device_token)
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;

        let Some(dequeued) =
            PluginShmemOrdering::dequeue_inbound_frame(inbound_ring.header, inbound_ring.entries)
                .map_err(|source| BlockIoError::RingDequeue {
                ring_index: self.inbound_ring_index,
                source,
            })?
        else {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: head.delivery_key(),
                actual: None,
            });
        };
        if dequeued.delivery_key() != head.delivery_key() {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: head.delivery_key(),
                actual: Some(dequeued.delivery_key()),
            });
        }

        self.completed_identities
            .borrow_mut()
            .record(response.identity());

        deliver
            .complete_block_response(&response)
            .map_err(|source| BlockIoError::GuestCompletion {
                request_id: response.request_id(),
                release,
                source,
            })?;
        Ok(BlockPoll::Completed { response, release })
    }

    /// Peeks one post-primary duplicate or reset event at the transport boundary.
    ///
    /// A primary response at the ring head is left for its request-token poll.
    /// Only an identity already completed by this transport can be consumed
    /// here, which prevents the asynchronous event path from stealing ordinary
    /// I/O completions.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] for malformed frames, invalid reset epochs,
    /// ring races, or a reset that cannot be applied exactly.
    pub fn peek_transport_event(
        &self,
        inbound_ring: &BlockInboundRing<'_>,
        current_icount: u64,
    ) -> Result<Option<PendingBlockTransportEvent>, BlockIoError> {
        self.check_inbound_ring(inbound_ring)?;
        let Some(head) = peek_head_frame(inbound_ring)? else {
            return Ok(None);
        };
        if head.delivery_icount > current_icount {
            return Ok(None);
        }
        if head.src_node != self.block_slot {
            return Err(BlockIoError::UnexpectedTransportEventSource {
                expected_src_node: self.block_slot,
                actual_src_node: head.src_node,
                frame: head.delivery_key(),
            });
        }
        let payload = head
            .payload()
            .map_err(|source| BlockIoError::TransportEventMalformed {
                frame: head.delivery_key(),
                source: BlockWireError::FramePayload { source },
            })?;
        let response = BlockResponse::decode(payload).map_err(|source| {
            BlockIoError::TransportEventMalformed {
                frame: head.delivery_key(),
                source,
            }
        })?;
        if matches!(
            response.status(),
            BlockResponseStatus::Ok | BlockResponseStatus::Error
        ) {
            return Ok(None);
        }
        if !self
            .completed_identities
            .borrow()
            .contains(response.identity())
        {
            return Err(BlockIoError::UnknownTransportEventIdentity {
                identity: response.identity(),
                frame: head.delivery_key(),
            });
        }
        // Fully decode and validate the event before advancing the shared
        // ring. A malformed reset must remain at the head so the fail-closed
        // error is reproducible and cannot expose a partially applied epoch.
        let event = match response.status() {
            BlockResponseStatus::DuplicateIgnored => BlockTransportEvent::IgnoredDuplicate {
                identity: response.identity(),
            },
            BlockResponseStatus::DuplicateProtocolError => BlockTransportEvent::ProtocolError {
                identity: response.identity(),
                error: response.error_code().map_err(|source| {
                    BlockIoError::TransportEventMalformed {
                        frame: head.delivery_key(),
                        source,
                    }
                })?,
            },
            BlockResponseStatus::Ok
            | BlockResponseStatus::Error
            | BlockResponseStatus::RetryPreserveId
            | BlockResponseStatus::RetryNewId
            | BlockResponseStatus::DropCompletion => return Ok(None),
            BlockResponseStatus::TransportReset => {
                let reset = response.transport_reset().map_err(|source| {
                    BlockIoError::TransportEventMalformed {
                        frame: head.delivery_key(),
                        source,
                    }
                })?;
                let current_epoch = self.request_epoch.get();
                match reset.request_ids {
                    BlockTransportRequestIds::PreserveMonotonic
                        if reset.next_epoch == current_epoch => {}
                    BlockTransportRequestIds::NewEpochFromZero
                        if current_epoch.checked_add(1) == Some(reset.next_epoch) => {}
                    _ => {
                        return Err(BlockIoError::InvalidTransportResetEpoch {
                            current_epoch,
                            next_epoch: reset.next_epoch,
                            request_ids: reset.request_ids,
                        });
                    }
                }
                BlockTransportEvent::Reset {
                    identity: response.identity(),
                    reset,
                }
            }
        };
        Ok(Some(PendingBlockTransportEvent {
            event,
            frame: head.delivery_key(),
        }))
    }

    /// Commits a previously peeked transport event after QEMU accepts it.
    ///
    /// This is the second phase of the transport-event transaction. The event
    /// remains at the shared-memory ring head and no plugin state changes until
    /// this method verifies and dequeues the exact frame returned by
    /// [`Self::peek_transport_event`].
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] when the ring changed between prepare and
    /// commit or the event can no longer be consumed exactly.
    pub fn commit_transport_event(
        &self,
        inbound_ring: &BlockInboundRing<'_>,
        pending: PendingBlockTransportEvent,
    ) -> Result<BlockTransportEvent, BlockIoError> {
        self.check_inbound_ring(inbound_ring)?;
        let Some(head) = peek_head_frame(inbound_ring)? else {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: pending.frame,
                actual: None,
            });
        };
        if head.delivery_key() != pending.frame {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: pending.frame,
                actual: Some(head.delivery_key()),
            });
        }
        let Some(dequeued) =
            PluginShmemOrdering::dequeue_inbound_frame(inbound_ring.header, inbound_ring.entries)
                .map_err(|source| BlockIoError::RingDequeue {
                ring_index: self.inbound_ring_index,
                source,
            })?
        else {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: pending.frame,
                actual: None,
            });
        };
        if dequeued.delivery_key() != pending.frame {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: pending.frame,
                actual: Some(dequeued.delivery_key()),
            });
        }
        if let BlockTransportEvent::Reset { reset, .. } = pending.event {
            if reset.request_ids == BlockTransportRequestIds::NewEpochFromZero {
                self.request_epoch.set(reset.next_epoch);
                self.next_request_id.set(0);
            }
            if !reset.preserve_duplicate_history {
                self.completed_identities.borrow_mut().clear();
            }
        }
        Ok(pending.event)
    }

    fn fail_polled_request(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        token: BlockRequestToken,
    ) -> Result<DeviceIoRequestRelease, BlockIoError> {
        freeze
            .fail_request(slot, token.device_token)
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })
    }

    fn check_outbound_ring(&self, ring: &BlockOutboundRing<'_>) -> Result<(), BlockIoError> {
        if ring.ring_index != self.outbound_ring_index
            || ring.src_slot != self.vm_slot
            || ring.dst_slot != self.block_slot
        {
            Err(BlockIoError::WrongOutboundRing {
                expected_src_slot: self.vm_slot,
                expected_dst_slot: self.block_slot,
                expected_ring_index: Some(self.outbound_ring_index),
                actual_src_slot: ring.src_slot,
                actual_dst_slot: ring.dst_slot,
                actual_ring_index: ring.ring_index,
            })
        } else {
            Ok(())
        }
    }

    fn check_inbound_ring(&self, ring: &BlockInboundRing<'_>) -> Result<(), BlockIoError> {
        if ring.ring_index != self.inbound_ring_index
            || ring.src_slot != self.block_slot
            || ring.dst_slot != self.vm_slot
        {
            Err(BlockIoError::WrongInboundRing {
                expected_src_slot: self.block_slot,
                expected_dst_slot: self.vm_slot,
                expected_ring_index: Some(self.inbound_ring_index),
                actual_src_slot: ring.src_slot,
                actual_dst_slot: ring.dst_slot,
                actual_ring_index: ring.ring_index,
            })
        } else {
            Ok(())
        }
    }
}

/// Handles one safe block submit callback body.
///
/// # Errors
///
/// Returns [`BlockIoError`] when submit validation, freeze state, or ring enqueue
/// fails.
pub fn handle_block_submit_callback(
    block_io: &PluginBlockIo,
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    outbound_ring: &mut BlockOutboundRing<'_>,
    submit_icount: u64,
    request: &BlockRequest,
) -> Result<BlockSubmit, BlockIoError> {
    block_io.submit_request(freeze, slot, outbound_ring, submit_icount, request)
}

/// Handles one safe block poll callback body.
///
/// # Errors
///
/// Returns [`BlockIoError`] when ring validation, response decoding, delivery, or
/// freeze-token completion fails.
pub fn handle_block_poll_callback<D>(
    block_io: &PluginBlockIo,
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    inbound_ring: &BlockInboundRing<'_>,
    deliver: &mut D,
    current_icount: u64,
    token: BlockRequestToken,
) -> Result<BlockPoll, BlockIoError>
where
    D: BlockGuestCompletion + ?Sized,
{
    block_io.poll_response(freeze, slot, inbound_ring, deliver, current_icount, token)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let field = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
    ]))
}

fn peek_head_frame(ring: &BlockInboundRing<'_>) -> Result<Option<FrameEntry>, BlockIoError> {
    let Some(delivery_icount) =
        PluginShmemOrdering::peek_inbound_delivery_icount(ring.header, ring.entries).map_err(
            |source| BlockIoError::RingDequeue {
                ring_index: ring.ring_index,
                source,
            },
        )?
    else {
        return Ok(None);
    };
    let slot = (PluginShmemOrdering::consumer_read_index(ring.header)
        & (ring.entries.len() as u64 - 1)) as usize;
    let frame = ring.entries[slot].clone();
    if frame.delivery_icount != delivery_icount {
        return Err(BlockIoError::DequeuedUnexpectedFrame {
            ring_index: ring.ring_index,
            expected: FrameDeliveryKey {
                delivery_icount,
                src_node: frame.src_node,
                seq: frame.seq,
            },
            actual: Some(frame.delivery_key()),
        });
    }
    Ok(Some(frame))
}

#[cfg(test)]
#[path = "block_io_tests.rs"]
mod tests;
