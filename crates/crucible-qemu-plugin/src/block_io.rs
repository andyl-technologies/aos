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

mod history;
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
    pub fn from_directed_rings(
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
    pub const fn new(vm_slot: u32, outbound_ring_index: u32, inbound_ring_index: u32) -> Self {
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

/// A mutable view of the outbound block executor ring.
pub struct BlockOutboundRing<'a> {
    ring_index: u32,
    src_slot: u32,
    dst_slot: u32,
    header: &'a RingHeader,
    entries: &'a mut [FrameEntry],
}

impl<'a> BlockOutboundRing<'a> {
    /// Builds an outbound block ring view.
    #[must_use]
    pub fn new(
        ring_index: u32,
        src_slot: u32,
        dst_slot: u32,
        header: &'a RingHeader,
        entries: &'a mut [FrameEntry],
    ) -> Self {
        Self {
            ring_index,
            src_slot,
            dst_slot,
            header,
            entries,
        }
    }
}

/// An immutable consumer view of the inbound block executor ring.
#[derive(Clone, Copy)]
pub struct BlockInboundRing<'a> {
    ring_index: u32,
    src_slot: u32,
    dst_slot: u32,
    header: &'a RingHeader,
    entries: &'a [FrameEntry],
}

impl<'a> BlockInboundRing<'a> {
    /// Builds an inbound block ring view.
    #[must_use]
    pub const fn new(
        ring_index: u32,
        src_slot: u32,
        dst_slot: u32,
        header: &'a RingHeader,
        entries: &'a [FrameEntry],
    ) -> Self {
        Self {
            ring_index,
            src_slot,
            dst_slot,
            header,
            entries,
        }
    }
}

/// A guest block operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOperation {
    /// Read bytes from the block image.
    Read,
    /// Write bytes to the block overlay.
    Write,
    /// Flush pending writes.
    Flush,
    /// Query the device length.
    GetLength,
    /// Discard a payload-free byte range.
    Discard,
}

impl BlockOperation {
    const fn wire_type(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Flush => 2,
            Self::GetLength => 3,
            Self::Discard => 4,
        }
    }

    fn from_wire(operation: u8) -> Result<Self, BlockWireError> {
        match operation {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Flush),
            3 => Ok(Self::GetLength),
            4 => Ok(Self::Discard),
            other => Err(BlockWireError::UnknownOperation { operation: other }),
        }
    }
}

/// A guest block request before it is assigned a wire request id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequest {
    operation: BlockOperation,
    offset: u64,
    count: u32,
    payload: Vec<u8>,
}

impl BlockRequest {
    /// Builds a read request.
    #[must_use]
    pub const fn read(offset: u64, count: u32) -> Self {
        Self {
            operation: BlockOperation::Read,
            offset,
            count,
            payload: Vec::new(),
        }
    }

    /// Builds a write request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::PayloadLengthOverflow`] when the write payload
    /// length cannot fit in the wire-format `count` field.
    pub fn write(offset: u64, payload: Vec<u8>) -> Result<Self, BlockWireError> {
        let count = u32::try_from(payload.len())
            .map_err(|_| BlockWireError::PayloadLengthOverflow { len: payload.len() })?;
        Ok(Self {
            operation: BlockOperation::Write,
            offset,
            count,
            payload,
        })
    }

    /// Builds a flush request.
    #[must_use]
    pub const fn flush() -> Self {
        Self {
            operation: BlockOperation::Flush,
            offset: 0,
            count: 0,
            payload: Vec::new(),
        }
    }

    /// Builds a get-length request.
    #[must_use]
    pub const fn get_length() -> Self {
        Self {
            operation: BlockOperation::GetLength,
            offset: 0,
            count: 0,
            payload: Vec::new(),
        }
    }

    /// Builds a payload-free discard request.
    #[must_use]
    pub const fn discard(offset: u64, count: u32) -> Self {
        Self {
            operation: BlockOperation::Discard,
            offset,
            count,
            payload: Vec::new(),
        }
    }

    /// Returns the operation kind.
    #[must_use]
    pub const fn operation(&self) -> BlockOperation {
        self.operation
    }

    /// Returns the byte offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the requested byte count.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the write payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes a request in the block wire format with the supplied request id.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] when the request payload is inconsistent with
    /// the operation kind or the encoded frame would exceed the shared-memory
    /// frame payload capacity.
    pub fn encode(&self, identity: BlockRequestIdentity) -> Result<Vec<u8>, BlockWireError> {
        if self.operation == BlockOperation::Write && self.payload.len() != self.count as usize {
            return Err(BlockWireError::CountPayloadMismatch {
                count: self.count,
                payload_len: self.payload.len(),
            });
        }
        if self.operation != BlockOperation::Write && !self.payload.is_empty() {
            return Err(BlockWireError::UnexpectedPayload {
                operation: self.operation,
                payload_len: self.payload.len(),
            });
        }
        let payload_len = BLOCK_REQUEST_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(BlockWireError::PayloadLengthOverflow {
                len: self.payload.len(),
            })?;
        if payload_len > MAX_FRAME_DATA {
            return Err(BlockWireError::FramePayload {
                source: FrameEntryError::PayloadLengthExceedsCapacity {
                    len: payload_len,
                    capacity: MAX_FRAME_DATA,
                },
            });
        }
        let mut out = Vec::with_capacity(payload_len);
        out.push(self.operation.wire_type());
        out.push(BLOCK_WIRE_VERSION);
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&identity.epoch.to_le_bytes());
        out.extend_from_slice(&identity.request_id.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a request from the block wire format.
    ///
    /// The returned tuple contains the wire request id and the logical request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] when the payload is shorter than the fixed
    /// header, uses an unsupported version or operation, carries nonzero
    /// reserved bits, or contains an operation-inconsistent body.
    pub fn decode(payload: &[u8]) -> Result<(BlockRequestIdentity, Self), BlockWireError> {
        if payload.len() < BLOCK_REQUEST_HEADER_LEN {
            return Err(BlockWireError::ShortRequest { len: payload.len() });
        }
        let operation = BlockOperation::from_wire(payload[0])?;
        if payload[1] != BLOCK_WIRE_VERSION {
            return Err(BlockWireError::UnsupportedVersion {
                version: payload[1],
            });
        }
        let reserved = u16::from_le_bytes(
            payload[2..4]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        if reserved != 0 {
            return Err(BlockWireError::NonZeroReserved { reserved });
        }
        let epoch = u64::from_le_bytes(
            payload[4..12]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let request_id = u32::from_le_bytes(
            payload[12..16]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let offset = u64::from_le_bytes(
            payload[16..24]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let count = u32::from_le_bytes(
            payload[24..28]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let payload_bytes = &payload[BLOCK_REQUEST_HEADER_LEN..];
        match operation {
            BlockOperation::Write => {
                let count_usize = usize::try_from(count)
                    .map_err(|_| BlockWireError::CountLengthOverflow { count })?;
                if count_usize > payload_bytes.len() {
                    return Err(BlockWireError::RequestCountExceedsPayload {
                        count,
                        available: payload_bytes.len(),
                    });
                }
                if count_usize != payload_bytes.len() {
                    return Err(BlockWireError::RequestCountPayloadMismatch {
                        count,
                        payload_len: payload_bytes.len(),
                    });
                }
                Ok((
                    BlockRequestIdentity::new(epoch, request_id),
                    Self {
                        operation,
                        offset,
                        count,
                        payload: payload_bytes.to_vec(),
                    },
                ))
            }
            _ if !payload_bytes.is_empty() => Err(BlockWireError::UnexpectedPayload {
                operation,
                payload_len: payload_bytes.len(),
            }),
            _ => Ok((
                BlockRequestIdentity::new(epoch, request_id),
                Self {
                    operation,
                    offset,
                    count,
                    payload: Vec::new(),
                },
            )),
        }
    }
}

/// A block executor response ready to expose to the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockResponse {
    status: BlockResponseStatus,
    identity: BlockRequestIdentity,
    request_id: u32,
    payload: Vec<u8>,
}

impl BlockResponse {
    /// Builds a response for tests and callback adapters.
    #[must_use]
    pub fn new(status: BlockResponseStatus, request_id: u32, payload: Vec<u8>) -> Self {
        Self::with_identity(status, BlockRequestIdentity::new(0, request_id), payload)
    }

    /// Builds a response with an explicit epoch-scoped request identity.
    #[must_use]
    pub fn with_identity(
        status: BlockResponseStatus,
        identity: BlockRequestIdentity,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            status,
            identity,
            request_id: identity.request_id,
            payload,
        }
    }

    /// Builds a live transport-reset event for an already-completed request.
    #[must_use]
    pub fn reset_event(identity: BlockRequestIdentity, reset: BlockTransportReset) -> Self {
        Self::with_identity(
            BlockResponseStatus::TransportReset,
            identity,
            reset.encode().to_vec(),
        )
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> BlockResponseStatus {
        self.status
    }

    /// Returns the echoed request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// Returns the epoch-scoped request identity echoed by the response.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        self.identity
    }

    /// Returns the response payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the typed block error for a failed response.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::InvalidErrorPayload`] unless this is an error
    /// response carrying exactly one defined result byte.
    pub fn error_code(&self) -> Result<BlockResponseErrorCode, BlockWireError> {
        if !matches!(
            self.status,
            BlockResponseStatus::Error | BlockResponseStatus::DuplicateProtocolError
        ) || self.payload.len() != 1
        {
            return Err(BlockWireError::InvalidErrorPayload {
                status: self.status.wire_status(),
                len: self.payload.len(),
            });
        }
        BlockResponseErrorCode::from_wire(self.payload[0])
    }

    /// Returns the decoded live transport-reset transition.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::InvalidResetPayload`] unless this response is
    /// a reset with the exact closed payload shape.
    pub fn transport_reset(&self) -> Result<BlockTransportReset, BlockWireError> {
        if self.status != BlockResponseStatus::TransportReset {
            return Err(BlockWireError::InvalidResetPayload {
                len: self.payload.len(),
            });
        }
        BlockTransportReset::decode(&self.payload)
    }

    /// Encodes a response in the block wire format.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::PayloadLengthOverflow`] when the response
    /// payload length cannot fit in the wire-format `count` field or cannot be
    /// added to the fixed header length.
    pub fn encode(&self) -> Result<Vec<u8>, BlockWireError> {
        let count = u32::try_from(self.payload.len()).map_err(|_| {
            BlockWireError::PayloadLengthOverflow {
                len: self.payload.len(),
            }
        })?;
        let payload_len = BLOCK_RESPONSE_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(BlockWireError::PayloadLengthOverflow {
                len: self.payload.len(),
            })?;
        let mut out = Vec::with_capacity(payload_len);
        out.push(self.status.wire_status());
        out.push(BLOCK_WIRE_VERSION);
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&self.identity.epoch.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a response from the block wire format.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] when the payload is shorter than the fixed
    /// header, uses an unsupported version or status, carries nonzero reserved
    /// bits, or has a `count` field that does not exactly match the payload
    /// bytes that follow the header.
    pub fn decode(payload: &[u8]) -> Result<Self, BlockWireError> {
        if payload.len() < BLOCK_RESPONSE_HEADER_LEN {
            return Err(BlockWireError::ShortResponse { len: payload.len() });
        }
        let status = BlockResponseStatus::from_wire(payload[0])?;
        if payload[1] != BLOCK_WIRE_VERSION {
            return Err(BlockWireError::UnsupportedVersion {
                version: payload[1],
            });
        }
        let reserved = u16::from_le_bytes(
            payload[2..4]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        if reserved != 0 {
            return Err(BlockWireError::NonZeroReserved { reserved });
        }
        let epoch = u64::from_le_bytes(
            payload[4..12]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let request_id = u32::from_le_bytes(
            payload[12..16]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let count = u32::from_le_bytes(
            payload[16..20]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let count_usize =
            usize::try_from(count).map_err(|_| BlockWireError::CountLengthOverflow { count })?;
        let actual = payload.len() - BLOCK_RESPONSE_HEADER_LEN;
        if count_usize > actual {
            return Err(BlockWireError::CountExceedsPayload {
                count,
                available: actual,
            });
        }
        if count_usize != actual {
            return Err(BlockWireError::ResponseCountPayloadMismatch {
                count,
                payload_len: actual,
            });
        }
        let response = Self {
            status,
            identity: BlockRequestIdentity::new(epoch, request_id),
            request_id,
            payload: payload[BLOCK_RESPONSE_HEADER_LEN..BLOCK_RESPONSE_HEADER_LEN + count_usize]
                .to_vec(),
        };
        if matches!(
            status,
            BlockResponseStatus::Error | BlockResponseStatus::DuplicateProtocolError
        ) {
            response.error_code()?;
        } else if status == BlockResponseStatus::TransportReset {
            response.transport_reset()?;
        }
        Ok(response)
    }
}

/// Block response status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockResponseStatus {
    /// Request completed successfully.
    Ok,
    /// Request completed with a device error.
    Error,
    /// Completion requesting a live guest transport reset.
    TransportReset,
    /// Protocol-valid duplicate consumed without a guest completion.
    DuplicateIgnored,
    /// Duplicate carrying a typed protocol error.
    DuplicateProtocolError,
    /// Outstanding request must retry with its existing identity.
    RetryPreserveId,
    /// Outstanding request must retry with a new post-reset identity.
    RetryNewId,
    /// Outstanding completion is intentionally dropped.
    DropCompletion,
}

/// Post-reset request-ID allocation rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportRequestIds {
    /// Keeps the current epoch and monotone counter.
    PreserveMonotonic,
    /// Switches to the supplied epoch and restarts from zero.
    NewEpochFromZero,
}

/// Request treatment while reset recovery blocks admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportUnadmitted {
    /// Rejects the request.
    Reject,
    /// Holds the request until recovery.
    WaitForRecovery,
}

/// Treatment of queued or executing requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportPending {
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
}

/// Treatment of resolved requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportResolved {
    /// Completes the result.
    Complete,
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
}

/// Treatment of completed but undelivered requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportUndelivered {
    /// Delivers the existing result.
    Complete,
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
    /// Drops the completion.
    DropCompletion,
}

/// Decoded live block-transport reset transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockTransportReset {
    /// Epoch active after reset.
    pub next_epoch: u64,
    /// Exact virtual recovery duration.
    pub recovery_nanos: u64,
    /// Post-reset ID allocation.
    pub request_ids: BlockTransportRequestIds,
    /// Whether QEMU must re-enumerate the declared topology.
    pub reenumerate_declared: bool,
    /// Whether old duplicate identities remain suppressed.
    pub preserve_duplicate_history: bool,
    /// Typed failure used by failed request stages.
    pub failure_result: BlockResponseErrorCode,
    /// Admission treatment during recovery.
    pub unadmitted: BlockTransportUnadmitted,
    /// Queued request treatment.
    pub queued: BlockTransportPending,
    /// Executing request treatment.
    pub executing: BlockTransportPending,
    /// Resolved request treatment.
    pub resolved: BlockTransportResolved,
    /// Completed-undelivered request treatment.
    pub completed_undelivered: BlockTransportUndelivered,
    /// Whether the controller buffer survives.
    pub preserve_controller_buffer: bool,
    /// Whether the volatile cache survives.
    pub preserve_volatile_cache: bool,
}

impl BlockTransportReset {
    const PAYLOAD_LEN: usize = 32;

    fn encode(self) -> [u8; Self::PAYLOAD_LEN] {
        let mut payload = [0_u8; Self::PAYLOAD_LEN];
        payload[..8].copy_from_slice(&self.next_epoch.to_le_bytes());
        payload[8..16].copy_from_slice(&self.recovery_nanos.to_le_bytes());
        payload[16] = match self.request_ids {
            BlockTransportRequestIds::PreserveMonotonic => 0,
            BlockTransportRequestIds::NewEpochFromZero => 1,
        };
        payload[17] = u8::from(self.reenumerate_declared);
        payload[18] = u8::from(self.preserve_duplicate_history);
        payload[19] = self.failure_result.to_wire();
        payload[20] = match self.unadmitted {
            BlockTransportUnadmitted::Reject => 0,
            BlockTransportUnadmitted::WaitForRecovery => 1,
        };
        payload[21] = encode_transport_pending(self.queued);
        payload[22] = encode_transport_pending(self.executing);
        payload[23] = match self.resolved {
            BlockTransportResolved::Complete => 0,
            BlockTransportResolved::Fail => 1,
            BlockTransportResolved::RetryPreserveId => 2,
            BlockTransportResolved::RetryNewId => 3,
        };
        payload[24] = match self.completed_undelivered {
            BlockTransportUndelivered::Complete => 0,
            BlockTransportUndelivered::Fail => 1,
            BlockTransportUndelivered::RetryPreserveId => 2,
            BlockTransportUndelivered::RetryNewId => 3,
            BlockTransportUndelivered::DropCompletion => 4,
        };
        payload[25] = u8::from(self.preserve_controller_buffer);
        payload[26] = u8::from(self.preserve_volatile_cache);
        payload
    }

    fn decode(payload: &[u8]) -> Result<Self, BlockWireError> {
        if payload.len() != Self::PAYLOAD_LEN || payload[27..].iter().any(|byte| *byte != 0) {
            return Err(BlockWireError::InvalidResetPayload { len: payload.len() });
        }
        let request_ids = match payload[16] {
            0 => BlockTransportRequestIds::PreserveMonotonic,
            1 => BlockTransportRequestIds::NewEpochFromZero,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let reenumerate_declared = match payload[17] {
            0 => false,
            1 => true,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let preserve_duplicate_history = match payload[18] {
            0 => false,
            1 => true,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let failure_result = BlockResponseErrorCode::from_wire(payload[19])?;
        let unadmitted = match payload[20] {
            0 => BlockTransportUnadmitted::Reject,
            1 => BlockTransportUnadmitted::WaitForRecovery,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let queued = decode_transport_pending(payload[21], payload.len())?;
        let executing = decode_transport_pending(payload[22], payload.len())?;
        let resolved = match payload[23] {
            0 => BlockTransportResolved::Complete,
            1 => BlockTransportResolved::Fail,
            2 => BlockTransportResolved::RetryPreserveId,
            3 => BlockTransportResolved::RetryNewId,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let completed_undelivered = match payload[24] {
            0 => BlockTransportUndelivered::Complete,
            1 => BlockTransportUndelivered::Fail,
            2 => BlockTransportUndelivered::RetryPreserveId,
            3 => BlockTransportUndelivered::RetryNewId,
            4 => BlockTransportUndelivered::DropCompletion,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let preserve_controller_buffer = decode_transport_bool(payload[25], payload.len())?;
        let preserve_volatile_cache = decode_transport_bool(payload[26], payload.len())?;
        let mut epoch = [0_u8; 8];
        epoch.copy_from_slice(&payload[..8]);
        let mut recovery = [0_u8; 8];
        recovery.copy_from_slice(&payload[8..16]);
        Ok(Self {
            next_epoch: u64::from_le_bytes(epoch),
            recovery_nanos: u64::from_le_bytes(recovery),
            request_ids,
            reenumerate_declared,
            preserve_duplicate_history,
            failure_result,
            unadmitted,
            queued,
            executing,
            resolved,
            completed_undelivered,
            preserve_controller_buffer,
            preserve_volatile_cache,
        })
    }
}

fn decode_transport_pending(byte: u8, len: usize) -> Result<BlockTransportPending, BlockWireError> {
    match byte {
        0 => Ok(BlockTransportPending::Fail),
        1 => Ok(BlockTransportPending::RetryPreserveId),
        2 => Ok(BlockTransportPending::RetryNewId),
        _ => Err(BlockWireError::InvalidResetPayload { len }),
    }
}

fn encode_transport_pending(policy: BlockTransportPending) -> u8 {
    match policy {
        BlockTransportPending::Fail => 0,
        BlockTransportPending::RetryPreserveId => 1,
        BlockTransportPending::RetryNewId => 2,
    }
}

fn decode_transport_bool(byte: u8, len: usize) -> Result<bool, BlockWireError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BlockWireError::InvalidResetPayload { len }),
    }
}

/// Closed protocol-neutral error result on the block shared-memory ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockResponseErrorCode {
    /// Device unavailable.
    Offline,
    /// Write to read-only storage.
    ReadOnly,
    /// Invalid addressed range.
    InvalidRange,
    /// Controller or queue busy.
    Busy,
    /// Modeled timeout.
    Timeout,
    /// Uncorrectable medium error.
    MediumError,
    /// Integrity verification error.
    IntegrityError,
    /// Generic I/O error.
    IoError,
    /// Capacity exhausted.
    NoSpace,
    /// Namespace or object absent.
    NotFound,
    /// Stale retained identity.
    Stale,
}

impl BlockResponseErrorCode {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Offline => 1,
            Self::ReadOnly => 2,
            Self::InvalidRange => 3,
            Self::Busy => 4,
            Self::Timeout => 5,
            Self::MediumError => 6,
            Self::IntegrityError => 7,
            Self::IoError => 8,
            Self::NoSpace => 9,
            Self::NotFound => 10,
            Self::Stale => 11,
        }
    }

    fn from_wire(code: u8) -> Result<Self, BlockWireError> {
        match code {
            1 => Ok(Self::Offline),
            2 => Ok(Self::ReadOnly),
            3 => Ok(Self::InvalidRange),
            4 => Ok(Self::Busy),
            5 => Ok(Self::Timeout),
            6 => Ok(Self::MediumError),
            7 => Ok(Self::IntegrityError),
            8 => Ok(Self::IoError),
            9 => Ok(Self::NoSpace),
            10 => Ok(Self::NotFound),
            11 => Ok(Self::Stale),
            other => Err(BlockWireError::UnknownErrorCode { code: other }),
        }
    }
}

impl BlockResponseStatus {
    const fn wire_status(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Error => 1,
            Self::TransportReset => 2,
            Self::DuplicateIgnored => 3,
            Self::DuplicateProtocolError => 4,
            Self::RetryPreserveId => 5,
            Self::RetryNewId => 6,
            Self::DropCompletion => 7,
        }
    }

    fn from_wire(status: u8) -> Result<Self, BlockWireError> {
        match status {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Error),
            2 => Ok(Self::TransportReset),
            3 => Ok(Self::DuplicateIgnored),
            4 => Ok(Self::DuplicateProtocolError),
            5 => Ok(Self::RetryPreserveId),
            6 => Ok(Self::RetryNewId),
            7 => Ok(Self::DropCompletion),
            other => Err(BlockWireError::UnknownStatus { status: other }),
        }
    }
}

/// A request token that must be consumed by poll completion or failure handling.
#[must_use = "block request tokens must be consumed by block poll completion or failure"]
#[derive(Debug, PartialEq, Eq)]
pub struct BlockRequestToken {
    identity: BlockRequestIdentity,
    device_token: DeviceIoRequestToken,
}

impl BlockRequestToken {
    /// Returns the block wire request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.identity.request_id
    }

    /// Returns the epoch-scoped wire request identity.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        self.identity
    }

    /// Returns the submit icount carried by the device-I/O token.
    #[must_use]
    pub const fn submit_icount(&self) -> u64 {
        self.device_token.submit_icount()
    }
}

/// Metadata returned after one successful block submit.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockSubmit {
    ring_index: u32,
    submit_icount: u64,
    request_id: u32,
    payload_len: usize,
    token: BlockRequestToken,
}

impl BlockSubmit {
    /// Returns the outbound ring index.
    #[must_use]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    /// Returns the submit icount stamped onto the frame.
    #[must_use]
    pub const fn submit_icount(&self) -> u64 {
        self.submit_icount
    }

    /// Returns the assigned request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// Returns the encoded wire payload length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Consumes this submit metadata and returns the completion token.
    pub fn into_token(self) -> BlockRequestToken {
        self.token
    }
}

/// The result of one block poll callback.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockPoll {
    /// No matching response is ready; the token is returned to the caller.
    NotReady {
        /// The still-pending request token.
        token: BlockRequestToken,
    },
    /// A due response was delivered and the freeze token was released.
    Completed {
        /// The decoded response delivered to the guest.
        response: BlockResponse,
        /// Device-I/O release metadata.
        release: DeviceIoRequestRelease,
    },
}

/// One post-primary guest-transport event consumed independently of a request token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportEvent {
    /// A duplicate success completion was suppressed by transport history.
    IgnoredDuplicate {
        /// Identity of the already-completed request.
        identity: BlockRequestIdentity,
    },
    /// A duplicate carried a modeled protocol error.
    ProtocolError {
        /// Identity of the already-completed request.
        identity: BlockRequestIdentity,
        /// Closed protocol error delivered by the host.
        error: BlockResponseErrorCode,
    },
    /// A duplicate initiated a live controller reset.
    Reset {
        /// Identity whose duplicate initiated the reset.
        identity: BlockRequestIdentity,
        /// Exact guest-facing transition.
        reset: BlockTransportReset,
    },
}

/// A validated transport event held at the ring head until QEMU commits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingBlockTransportEvent {
    event: BlockTransportEvent,
    frame: FrameDeliveryKey,
}

impl PendingBlockTransportEvent {
    /// Returns the decoded event without consuming the prepared transaction.
    #[must_use]
    pub const fn event(self) -> BlockTransportEvent {
        self.event
    }

    /// Encodes the prepared event for QEMU-side validation.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] if the fixed event payload cannot be encoded.
    pub fn encode(self) -> Result<Vec<u8>, BlockWireError> {
        self.event.encode()
    }
}

impl BlockTransportEvent {
    /// Encodes the event in the same versioned response envelope used by the
    /// shared-memory block transport.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] if the fixed event payload cannot be encoded.
    pub fn encode(self) -> Result<Vec<u8>, BlockWireError> {
        let response = match self {
            Self::IgnoredDuplicate { identity } => BlockResponse::with_identity(
                BlockResponseStatus::DuplicateIgnored,
                identity,
                Vec::new(),
            ),
            Self::ProtocolError { identity, error } => BlockResponse::with_identity(
                BlockResponseStatus::DuplicateProtocolError,
                identity,
                vec![error.to_wire()],
            ),
            Self::Reset { identity, reset } => BlockResponse::reset_event(identity, reset),
        };
        response.encode()
    }
}

/// A safe adapter for delivering a decoded response to QEMU's block device path.
pub trait BlockGuestCompletion {
    /// Completes one guest block request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockGuestCompletionError`] when the QEMU-facing completion path
    /// cannot expose the response and must fail loudly.
    fn complete_block_response(
        &mut self,
        response: &BlockResponse,
    ) -> Result<(), BlockGuestCompletionError>;
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

/// A loud guest-completion failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("block guest completion failed: {message}")]
pub struct BlockGuestCompletionError {
    message: String,
}

impl BlockGuestCompletionError {
    /// Builds a guest-completion error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An error produced by block callback handling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BlockIoError {
    /// A serialized plugin transport continuation was not exact and canonical.
    #[error("invalid block transport continuation: {reason}")]
    InvalidTransportContinuation {
        /// Stable fail-loud validation reason.
        reason: &'static str,
    },
    /// The callback was handed a ring other than the fixed outbound block ring.
    #[error(
        "block outbound ring mismatch: expected src={expected_src_slot} dst={expected_dst_slot} ring={expected_ring_index:?}, got src={actual_src_slot} dst={actual_dst_slot} ring={actual_ring_index}"
    )]
    WrongOutboundRing {
        /// The VM slot fixed at registration.
        expected_src_slot: u32,
        /// The block executor slot fixed at registration.
        expected_dst_slot: u32,
        /// The outbound ring index fixed at registration, if known.
        expected_ring_index: Option<u32>,
        /// The supplied ring's producer slot.
        actual_src_slot: u32,
        /// The supplied ring's consumer slot.
        actual_dst_slot: u32,
        /// The supplied ring's index.
        actual_ring_index: u32,
    },
    /// The callback was handed a ring other than the fixed inbound block ring.
    #[error(
        "block inbound ring mismatch: expected src={expected_src_slot} dst={expected_dst_slot} ring={expected_ring_index:?}, got src={actual_src_slot} dst={actual_dst_slot} ring={actual_ring_index}"
    )]
    WrongInboundRing {
        /// The block executor slot fixed at registration.
        expected_src_slot: u32,
        /// The VM slot fixed at registration.
        expected_dst_slot: u32,
        /// The inbound ring index fixed at registration, if known.
        expected_ring_index: Option<u32>,
        /// The supplied ring's producer slot.
        actual_src_slot: u32,
        /// The supplied ring's consumer slot.
        actual_dst_slot: u32,
        /// The supplied ring's index.
        actual_ring_index: u32,
    },
    /// The request id counter cannot represent another request.
    #[error("block request id overflow at {request_id}")]
    RequestIdOverflow {
        /// The exhausted request id.
        request_id: u32,
    },
    /// An asynchronous event frame came from the wrong node.
    #[error(
        "block transport event source {actual_src_node} does not match reserved block source {expected_src_node}"
    )]
    UnexpectedTransportEventSource {
        /// Reserved block executor slot.
        expected_src_node: u32,
        /// Frame producer.
        actual_src_node: u32,
        /// Frame identity.
        frame: FrameDeliveryKey,
    },
    /// An asynchronous transport event was malformed.
    #[error("block transport event at {frame:?} is malformed: {source}")]
    TransportEventMalformed {
        /// Frame identity.
        frame: FrameDeliveryKey,
        /// Closed wire error.
        source: BlockWireError,
    },
    /// An asynchronous event did not belong to a completed request.
    #[error("block transport event for unknown or outstanding identity {identity:?} at {frame:?}")]
    UnknownTransportEventIdentity {
        /// Identity claimed by the event.
        identity: BlockRequestIdentity,
        /// Frame identity retained for deterministic diagnostics.
        frame: FrameDeliveryKey,
    },
    /// Completed-identity history exceeded an authored resource limit.
    #[error(
        "block completed-identity history limit `{field}` refused current={current} requested={requested} configured={configured} hard={hard}"
    )]
    CompletedHistoryResourceLimit {
        /// Stable public resource-limit field.
        field: &'static str,
        /// Usage already owned before the refused reservation.
        current: u64,
        /// Additional atomic usage that was refused.
        requested: u64,
        /// Authored scenario ceiling.
        configured: u64,
        /// Immutable compiled ceiling.
        hard: u64,
    },
    /// A reset response did not describe the only valid next epoch.
    #[error(
        "block transport reset from epoch {current_epoch} to {next_epoch} violates {request_ids:?}"
    )]
    InvalidTransportResetEpoch {
        /// Epoch active before reset.
        current_epoch: u64,
        /// Requested post-reset epoch.
        next_epoch: u64,
        /// Allocation rule that constrained the epoch.
        request_ids: BlockTransportRequestIds,
    },
    /// Block wire encoding or decoding failed.
    #[error("block wire error: {source}")]
    Wire {
        /// The wire-format error.
        source: BlockWireError,
    },
    /// Constructing a shared-memory frame failed.
    #[error("block frame construction failed: {source}")]
    Frame {
        /// The frame construction error.
        source: FrameEntryError,
    },
    /// Device-I/O freeze state rejected a transition.
    #[error("block device-I/O freeze failed: {source}")]
    DeviceIoFreeze {
        /// The device-I/O freeze error.
        source: DeviceIoFreezeError,
    },
    /// The outbound request enqueue failed after the freeze token was created.
    #[error("block ring {ring_index} enqueue failed after freeze submit: {source}")]
    RingEnqueueFailed {
        /// The outbound ring index.
        ring_index: u32,
        /// The enqueue failure.
        source: SpscRingError,
        /// The release created by failing the just-created freeze token.
        release: DeviceIoRequestRelease,
    },
    /// The inbound ring operation failed.
    #[error("block ring {ring_index} dequeue failed: {source}")]
    RingDequeue {
        /// The inbound ring index.
        ring_index: u32,
        /// The dequeue failure.
        source: SpscRingError,
    },
    /// The inbound ring head could not be decoded as a block response.
    #[error("block ring {ring_index} malformed response at {frame:?}: {source}")]
    MalformedResponse {
        /// The inbound ring index.
        ring_index: u32,
        /// The frame key used to localize the malformed response.
        frame: FrameDeliveryKey,
        /// The decode error.
        source: BlockWireError,
        /// The request release created by failing the pending token.
        release: DeviceIoRequestRelease,
    },
    /// The due response frame was not produced by the reserved block executor.
    #[error(
        "block response source node {actual_src_node} does not match reserved block source {expected_src_node}"
    )]
    UnexpectedSource {
        /// The reserved block executor slot.
        expected_src_node: u32,
        /// The frame's advertised producer node.
        actual_src_node: u32,
        /// The response frame key.
        frame: FrameDeliveryKey,
        /// The request release created by failing the pending token.
        release: DeviceIoRequestRelease,
    },
    /// The due response did not match the request token being polled.
    #[error(
        "block response request id {actual_request_id} does not match token {expected_request_id}"
    )]
    UnexpectedResponse {
        /// The token's request id.
        expected_request_id: u32,
        /// The response request id.
        actual_request_id: u32,
        /// The response frame key.
        frame: FrameDeliveryKey,
        /// The request release created by failing the pending token.
        release: DeviceIoRequestRelease,
    },
    /// The dequeued response did not match the previously peeked head.
    #[error("block ring {ring_index} dequeued {actual:?} after peeking {expected:?}")]
    DequeuedUnexpectedFrame {
        /// The inbound ring index.
        ring_index: u32,
        /// The previewed frame key.
        expected: FrameDeliveryKey,
        /// The dequeued frame key, if any.
        actual: Option<FrameDeliveryKey>,
    },
    /// Delivering the decoded response to the guest failed.
    #[error("block request {request_id} guest completion failed: {source}")]
    GuestCompletion {
        /// The request id being completed.
        request_id: u32,
        /// The request release created before attempting guest completion.
        release: DeviceIoRequestRelease,
        /// The guest completion error.
        source: BlockGuestCompletionError,
    },
}

/// A block wire-format error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BlockWireError {
    /// A payload length cannot fit in a wire count.
    #[error("block payload length {len} cannot fit in u32")]
    PayloadLengthOverflow {
        /// The unrepresentable payload length.
        len: usize,
    },
    /// Request count did not match the write payload length.
    #[error("block request count {count} does not match payload length {payload_len}")]
    CountPayloadMismatch {
        /// The encoded count.
        count: u32,
        /// The actual payload length.
        payload_len: usize,
    },
    /// A non-write request carried a payload.
    #[error("block {operation:?} request unexpectedly carried {payload_len} payload bytes")]
    UnexpectedPayload {
        /// The operation that cannot carry request payload bytes.
        operation: BlockOperation,
        /// The unexpected payload length.
        payload_len: usize,
    },
    /// A frame payload length was invalid.
    #[error("block frame payload error: {source}")]
    FramePayload {
        /// The frame payload error.
        source: FrameEntryError,
    },
    /// Request is shorter than the fixed header.
    #[error("block request length {len} is shorter than header")]
    ShortRequest {
        /// The observed payload length.
        len: usize,
    },
    /// Request operation is unknown.
    #[error("block request operation {operation} is unknown")]
    UnknownOperation {
        /// The unknown operation byte.
        operation: u8,
    },
    /// Response is shorter than the fixed header.
    #[error("block response length {len} is shorter than header")]
    ShortResponse {
        /// The observed payload length.
        len: usize,
    },
    /// Block wire version is unsupported.
    #[error("block wire version {version} is unsupported")]
    UnsupportedVersion {
        /// The unsupported version byte.
        version: u8,
    },
    /// Block wire reserved header bits were nonzero.
    #[error("block wire reserved field {reserved} is nonzero")]
    NonZeroReserved {
        /// The decoded reserved field.
        reserved: u16,
    },
    /// Response status is unknown.
    #[error("block response status {status} is unknown")]
    UnknownStatus {
        /// The unknown status byte.
        status: u8,
    },
    /// Typed response error code is unknown.
    #[error("block response error code {code} is unknown")]
    UnknownErrorCode {
        /// The undefined typed-result byte.
        code: u8,
    },
    /// An error response does not carry exactly one typed-result byte.
    #[error("invalid block error payload for status {status}: length {len}")]
    InvalidErrorPayload {
        /// Response status wire byte.
        status: u8,
        /// Actual payload length.
        len: usize,
    },
    /// A transport-reset response has a malformed closed payload.
    #[error("invalid block transport-reset payload length {len}")]
    InvalidResetPayload {
        /// Actual reset payload length.
        len: usize,
    },
    /// Response count cannot be represented locally.
    #[error("block response count {count} cannot fit in usize")]
    CountLengthOverflow {
        /// The unrepresentable wire count.
        count: u32,
    },
    /// Request count exceeds the available payload bytes.
    #[error("block request count {count} exceeds available payload {available}")]
    RequestCountExceedsPayload {
        /// The declared request byte count.
        count: u32,
        /// The available payload bytes after the header.
        available: usize,
    },
    /// Request count did not exactly match the write payload length.
    #[error("block request count {count} does not match payload length {payload_len}")]
    RequestCountPayloadMismatch {
        /// The declared request byte count.
        count: u32,
        /// The actual payload length after the header.
        payload_len: usize,
    },
    /// Response count exceeds the available payload bytes.
    #[error("block response count {count} exceeds available payload {available}")]
    CountExceedsPayload {
        /// The declared response byte count.
        count: u32,
        /// The available payload bytes after the header.
        available: usize,
    },
    /// Response count did not exactly match the payload length.
    #[error("block response count {count} does not match payload length {payload_len}")]
    ResponseCountPayloadMismatch {
        /// The declared response byte count.
        count: u32,
        /// The actual payload length after the header.
        payload_len: usize,
    },
}

impl From<BlockWireError> for BlockIoError {
    fn from(source: BlockWireError) -> Self {
        Self::Wire { source }
    }
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
