//! Live block and 9p adapters for the QEMU callback ABI.
//!
//! The adapters retain request tokens across QEMU's submit/poll split, bind the
//! fixed executor rings selected from setup shared memory, and share one
//! device-I/O freeze state so block requests and 9p bursts cannot clear each
//! other's virtual-time hold.

use std::collections::{BTreeMap, BTreeSet};
use std::os::raw::{c_int, c_void};
use std::sync::{MutexGuard, TryLockError};

use crucible_shmem::{
    AcceleratorClass, AcceleratorEntry, DetachedPluginAcceleratorRings, FrameEntry, NodeSlot,
    RingHeader,
};
use thiserror::Error;

use crate::{
    BlockGuestCompletion, BlockGuestCompletionError, BlockInboundRing, BlockIoError,
    BlockOutboundRing, BlockPoll, BlockRequest, BlockRequestIdentity, BlockRequestToken,
    BlockResponse, BlockResponseErrorCode, BlockResponseStatus, BlockWireError,
    DeviceIoRequestToken, NinePGuestCompletion, NinePGuestCompletionError, NinePInboundRing,
    NinePIoError, NinePOutboundRing, NinePPoll, NinePRequest, NinePRequestToken, NinePResponse,
    PendingBlockTransportEvent, PluginBlockIo, PluginDeviceIoFreeze, PluginNinePIo,
    handle_9p_burst_done_callback, handle_9p_burst_start_callback, handle_9p_poll_callback,
    handle_9p_submit_callback, handle_block_poll_callback, handle_block_submit_callback,
};

use super::{
    LiveDirectedRingPair, LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState,
    StableDirectedRingHandle, abort_live_callback, callback_userdata_or_abort,
};

const QEMU_PLUGIN_BLOCK_POLL_PENDING: i64 = -2;
const QEMU_PLUGIN_BLOCK_RETRY_PRESERVE_ID: i64 = -3;
const QEMU_PLUGIN_BLOCK_RETRY_NEW_ID: i64 = -4;
const QEMU_PLUGIN_BLOCK_DROP_COMPLETION: i64 = -5;
const QEMU_PLUGIN_BLOCK_ERROR_BASE: i64 = 4096;
const QEMU_PLUGIN_BLOCK_EVENT_CAPACITY: usize = 52;
const QEMU_PLUGIN_BLOCK_TRANSPORT_SAVE_BUSY: i64 = -1;
const QEMU_PLUGIN_NINEP_POLL_PENDING: i64 = -2;
const QEMU_PLUGIN_ACCELERATOR_POLL_PENDING: i64 = -2;

pub(super) struct LiveDeviceCallbackState {
    freeze: PluginDeviceIoFreeze,
    block: PluginBlockIo,
    block_rings: LiveDirectedRingPair,
    block_tokens: BTreeMap<BlockRequestIdentity, BlockRequestToken>,
    block_retry_preserve: BTreeSet<BlockRequestIdentity>,
    pending_block_event: Option<PendingBlockTransportEvent>,
    ninep: PluginNinePIo,
    ninep_rings: LiveDirectedRingPair,
    ninep_tokens: BTreeMap<u32, PendingNinePRequest>,
    accelerator_generation: u64,
    accelerator_rings: DetachedPluginAcceleratorRings,
    accelerator_pending: BTreeMap<u64, PendingAcceleratorRequest>,
    accelerator_completed: BTreeMap<u64, AcceleratorEntry>,
}

struct PendingNinePRequest {
    token: NinePRequestToken,
    response_capacity: usize,
}

struct PendingAcceleratorRequest {
    token: DeviceIoRequestToken,
    device_id: [u8; 32],
    output_capacity: usize,
}

impl LiveDeviceCallbackState {
    pub(super) fn new(
        vm_slot: u32,
        block_rings: LiveDirectedRingPair,
        ninep_rings: LiveDirectedRingPair,
        accelerator_generation: u64,
        accelerator_rings: DetachedPluginAcceleratorRings,
    ) -> Result<Self, LiveDeviceCallbackError> {
        let block = PluginBlockIo::from_directed_rings(
            vm_slot,
            block_rings.outbound.descriptor,
            block_rings.inbound.descriptor,
        )
        .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        let ninep = PluginNinePIo::from_directed_rings(
            vm_slot,
            ninep_rings.outbound.descriptor,
            ninep_rings.inbound.descriptor,
        )
        .map_err(|source| LiveDeviceCallbackError::NineP { source })?;
        Ok(Self {
            freeze: PluginDeviceIoFreeze::new(),
            block,
            block_rings,
            block_tokens: BTreeMap::new(),
            block_retry_preserve: BTreeSet::new(),
            pending_block_event: None,
            ninep,
            ninep_rings,
            ninep_tokens: BTreeMap::new(),
            accelerator_generation,
            accelerator_rings,
            accelerator_pending: BTreeMap::new(),
            accelerator_completed: BTreeMap::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the public accelerator envelope has fixed fields"
    )]
    fn submit_accelerator(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        sequence: u64,
        device_id: [u8; 32],
        class_id: u16,
        job_kind: u16,
        queue_id: u16,
        service_units: u64,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<(), LiveDeviceCallbackError> {
        if self.accelerator_pending.contains_key(&sequence)
            || self.accelerator_completed.contains_key(&sequence)
        {
            return Err(LiveDeviceCallbackError::DuplicateAcceleratorSequence { sequence });
        }
        let class = match class_id {
            1 => AcceleratorClass::Gpu,
            2 => AcceleratorClass::Tpu,
            3 => AcceleratorClass::Fpga,
            _ => return Err(LiveDeviceCallbackError::UnknownAcceleratorClass { class_id }),
        };
        let entry = AcceleratorEntry::new(
            sequence,
            self.accelerator_generation,
            device_id,
            class,
            job_kind,
            queue_id,
            0,
            false,
            service_units,
            input,
        )
        .map_err(|source| LiveDeviceCallbackError::AcceleratorEntry { source })?;
        let token = self
            .freeze
            .begin_independent_submit(slot, current_icount)
            .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
        if let Err(source) = self.accelerator_rings.enqueue_request(entry) {
            self.freeze
                .fail_request(slot, token)
                .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
            return Err(LiveDeviceCallbackError::AcceleratorRing { source });
        }
        self.accelerator_pending.insert(
            sequence,
            PendingAcceleratorRequest {
                token,
                device_id,
                output_capacity,
            },
        );
        Ok(())
    }

    fn poll_accelerator(
        &mut self,
        slot: &NodeSlot,
        sequence: u64,
        output: &mut [u8],
    ) -> Result<(u16, i64), LiveDeviceCallbackError> {
        while let Some(entry) = self
            .accelerator_rings
            .dequeue_completion()
            .map_err(|source| LiveDeviceCallbackError::AcceleratorRing { source })?
        {
            let completion_sequence = entry.sequence();
            if !entry.is_completion() || entry.generation() != self.accelerator_generation {
                return Err(LiveDeviceCallbackError::InvalidAcceleratorCompletion {
                    sequence: completion_sequence,
                });
            }
            if self
                .accelerator_completed
                .insert(completion_sequence, entry)
                .is_some()
            {
                return Err(LiveDeviceCallbackError::DuplicateAcceleratorSequence {
                    sequence: completion_sequence,
                });
            }
        }
        let Some(completion) = self.accelerator_completed.remove(&sequence) else {
            return Ok((0, QEMU_PLUGIN_ACCELERATOR_POLL_PENDING));
        };
        let pending = self
            .accelerator_pending
            .remove(&sequence)
            .ok_or(LiveDeviceCallbackError::UnknownAcceleratorSequence { sequence })?;
        if completion.device_id() != pending.device_id {
            return Err(LiveDeviceCallbackError::InvalidAcceleratorCompletion { sequence });
        }
        let data = completion
            .data()
            .map_err(|source| LiveDeviceCallbackError::AcceleratorEntry { source })?;
        if data.len() > output.len() || data.len() > pending.output_capacity {
            return Err(LiveDeviceCallbackError::AcceleratorOutputTooLarge {
                sequence,
                len: data.len(),
                capacity: output.len(),
            });
        }
        output[..data.len()].copy_from_slice(data);
        self.freeze
            .complete_request(slot, pending.token)
            .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
        let len = i64::try_from(data.len()).map_err(|_error| {
            LiveDeviceCallbackError::ResponseLengthOverflow {
                family: "accelerator",
                len: data.len(),
            }
        })?;
        Ok((completion.status(), len))
    }

    // crucible-lint: allow rust-allow -- the adapter validates every fixed field in QEMU's block-submit ABI.
    #[allow(
        clippy::too_many_arguments,
        reason = "the adapter validates each fixed field in QEMU's block-submit ABI"
    )]
    fn submit_block(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        qemu_epoch: u64,
        qemu_request_id: u32,
        operation: u32,
        offset: u64,
        data: Option<&[u8]>,
        len: usize,
    ) -> Result<(), LiveDeviceCallbackError> {
        let qemu_identity = BlockRequestIdentity::new(qemu_epoch, qemu_request_id);
        let plugin_identity =
            BlockRequestIdentity::new(self.block.request_epoch(), self.block.next_request_id());
        let retry_preserve = self.block_retry_preserve.contains(&qemu_identity);
        if (!retry_preserve && plugin_identity != qemu_identity)
            || self.block_tokens.contains_key(&qemu_identity)
        {
            return Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "block",
                qemu_epoch,
                qemu_request_id,
                plugin_epoch: plugin_identity.epoch(),
                plugin_request_id: self.block.next_request_id(),
            });
        }
        let request = block_request(operation, offset, data, len)?;
        let mut outbound = self.block_rings.outbound.block_outbound();
        let submit = if retry_preserve {
            self.block.submit_retry_request(
                &mut self.freeze,
                slot,
                &mut outbound,
                current_icount,
                &request,
                qemu_identity,
            )
        } else {
            handle_block_submit_callback(
                &self.block,
                &mut self.freeze,
                slot,
                &mut outbound,
                current_icount,
                &request,
            )
        }
        .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        let token = submit.into_token();
        if token.identity() != qemu_identity {
            return Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "block",
                qemu_epoch,
                qemu_request_id,
                plugin_epoch: token.identity().epoch(),
                plugin_request_id: token.request_id(),
            });
        }
        self.block_tokens.insert(qemu_identity, token);
        if retry_preserve {
            let removed = self.block_retry_preserve.remove(&qemu_identity);
            debug_assert!(removed, "successful preserved retry had authorization");
        }
        Ok(())
    }

    fn poll_block(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        epoch: u64,
        request_id: u32,
        output: &mut [u8],
    ) -> Result<i64, LiveDeviceCallbackError> {
        let identity = BlockRequestIdentity::new(epoch, request_id);
        let token =
            self.block_tokens
                .remove(&identity)
                .ok_or(LiveDeviceCallbackError::UnknownRequest {
                    family: "block",
                    epoch,
                    request_id,
                })?;
        let inbound = self.block_rings.inbound.block_inbound();
        let mut completion = BlockOutput { output };
        match handle_block_poll_callback(
            &self.block,
            &mut self.freeze,
            slot,
            &inbound,
            &mut completion,
            current_icount,
            token,
        )
        .map_err(|source| LiveDeviceCallbackError::Block { source })?
        {
            BlockPoll::NotReady { token } => {
                self.block_tokens.insert(identity, token);
                Ok(QEMU_PLUGIN_BLOCK_POLL_PENDING)
            }
            BlockPoll::Completed { response, .. } => match response.status() {
                BlockResponseStatus::Ok => {
                    i64::try_from(response.payload().len()).map_err(|_error| {
                        LiveDeviceCallbackError::ResponseLengthOverflow {
                            family: "block",
                            len: response.payload().len(),
                        }
                    })
                }
                BlockResponseStatus::Error => {
                    let errno = block_error_errno(response.error_code().map_err(|source| {
                        LiveDeviceCallbackError::Block {
                            source: BlockIoError::Wire { source },
                        }
                    })?);
                    Ok(-(QEMU_PLUGIN_BLOCK_ERROR_BASE + errno))
                }
                BlockResponseStatus::TransportReset => {
                    Err(LiveDeviceCallbackError::UnexpectedBlockResetPrimary {
                        request_id: response.request_id(),
                    })
                }
                BlockResponseStatus::DuplicateIgnored
                | BlockResponseStatus::DuplicateProtocolError => {
                    Err(LiveDeviceCallbackError::UnexpectedBlockDuplicatePrimary {
                        request_id: response.request_id(),
                    })
                }
                BlockResponseStatus::RetryPreserveId => {
                    self.block_retry_preserve.insert(identity);
                    Ok(QEMU_PLUGIN_BLOCK_RETRY_PRESERVE_ID)
                }
                BlockResponseStatus::RetryNewId => Ok(QEMU_PLUGIN_BLOCK_RETRY_NEW_ID),
                BlockResponseStatus::DropCompletion => Ok(QEMU_PLUGIN_BLOCK_DROP_COMPLETION),
            },
        }
    }

    fn poll_block_event(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        output: &mut [u8],
    ) -> Result<i64, LiveDeviceCallbackError> {
        if output.len() < QEMU_PLUGIN_BLOCK_EVENT_CAPACITY {
            return Err(LiveDeviceCallbackError::ResponseBufferTooSmall {
                family: "block event",
                required: QEMU_PLUGIN_BLOCK_EVENT_CAPACITY,
                observed: output.len(),
            });
        }
        if self.pending_block_event.is_none() {
            let inbound = self.block_rings.inbound.block_inbound();
            self.pending_block_event = self
                .block
                .peek_transport_event(&inbound, current_icount)
                .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        }
        let Some(event) = self.pending_block_event else {
            return Ok(0);
        };
        let _slot = slot;
        let encoded = event
            .encode()
            .map_err(|source| LiveDeviceCallbackError::BlockWire { source })?;
        output[..encoded.len()].copy_from_slice(&encoded);
        i64::try_from(encoded.len()).map_err(|_error| {
            LiveDeviceCallbackError::ResponseLengthOverflow {
                family: "block event",
                len: encoded.len(),
            }
        })
    }

    fn commit_block_event(&mut self) -> Result<(), LiveDeviceCallbackError> {
        let pending = self
            .pending_block_event
            .ok_or(LiveDeviceCallbackError::NoPreparedBlockEvent)?;
        let inbound = self.block_rings.inbound.block_inbound();
        self.block
            .commit_transport_event(&inbound, pending)
            .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        self.pending_block_event = None;
        Ok(())
    }

    fn save_block_transport(&self, output: &mut [u8]) -> Result<usize, LiveDeviceCallbackError> {
        if !self.block_tokens.is_empty()
            || !self.block_retry_preserve.is_empty()
            || self.pending_block_event.is_some()
        {
            return Err(LiveDeviceCallbackError::TransportContinuationBusy {
                block_tokens: self.block_tokens.len(),
                retry_authorizations: self.block_retry_preserve.len(),
                prepared_event: self.pending_block_event.is_some(),
            });
        }
        let encoded = self
            .block
            .encode_transport_continuation()
            .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        if output.is_empty() {
            return Ok(encoded.len());
        }
        if output.len() < encoded.len() {
            return Err(LiveDeviceCallbackError::ResponseBufferTooSmall {
                family: "block transport continuation",
                required: encoded.len(),
                observed: output.len(),
            });
        }
        output[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }

    fn restore_block_transport(
        &mut self,
        encoded: &[u8],
        qemu_epoch: u64,
        qemu_next_request_id: u32,
    ) -> Result<(), LiveDeviceCallbackError> {
        if !self.block_tokens.is_empty()
            || !self.block_retry_preserve.is_empty()
            || self.pending_block_event.is_some()
        {
            return Err(LiveDeviceCallbackError::TransportContinuationBusy {
                block_tokens: self.block_tokens.len(),
                retry_authorizations: self.block_retry_preserve.len(),
                prepared_event: self.pending_block_event.is_some(),
            });
        }
        self.block
            .restore_transport_continuation(encoded, qemu_epoch, qemu_next_request_id)
            .map_err(|source| LiveDeviceCallbackError::Block { source })
    }

    fn begin_ninep_burst(&mut self, slot: &NodeSlot) -> Result<(), LiveDeviceCallbackError> {
        handle_9p_burst_start_callback(&self.ninep, &mut self.freeze, slot)
            .map(|_state| ())
            .map_err(|source| LiveDeviceCallbackError::NineP { source })
    }

    fn submit_ninep(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        qemu_request_id: u32,
        payload: &[u8],
        response_capacity: usize,
    ) -> Result<(), LiveDeviceCallbackError> {
        if i64::try_from(response_capacity).is_err() {
            return Err(LiveDeviceCallbackError::ResponseLengthOverflow {
                family: "9p capacity",
                len: response_capacity,
            });
        }
        if self.ninep.next_request_id() != qemu_request_id
            || self.ninep_tokens.contains_key(&qemu_request_id)
        {
            return Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "9p",
                qemu_epoch: 0,
                qemu_request_id,
                plugin_epoch: 0,
                plugin_request_id: self.ninep.next_request_id(),
            });
        }
        let request = NinePRequest::new(payload.to_vec());
        let mut outbound = self.ninep_rings.outbound.ninep_outbound();
        let submit = handle_9p_submit_callback(
            &self.ninep,
            &mut self.freeze,
            slot,
            &mut outbound,
            current_icount,
            &request,
        )
        .map_err(|source| LiveDeviceCallbackError::NineP { source })?;
        if submit.request_id() != qemu_request_id {
            return Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "9p",
                qemu_epoch: 0,
                qemu_request_id,
                plugin_epoch: 0,
                plugin_request_id: submit.request_id(),
            });
        }
        self.ninep_tokens.insert(
            qemu_request_id,
            PendingNinePRequest {
                token: submit.into_token(),
                response_capacity,
            },
        );
        Ok(())
    }

    fn poll_ninep(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        request_id: u32,
        output: &mut [u8],
    ) -> Result<i64, LiveDeviceCallbackError> {
        let registered_capacity = self
            .ninep_tokens
            .get(&request_id)
            .ok_or(LiveDeviceCallbackError::UnknownRequest {
                family: "9p",
                epoch: 0,
                request_id,
            })?
            .response_capacity;
        if output.len() < registered_capacity {
            return Err(LiveDeviceCallbackError::ResponseCapacityChanged {
                family: "9p",
                request_id,
                registered: registered_capacity,
                observed: output.len(),
            });
        }
        let pending = self.ninep_tokens.remove(&request_id).ok_or(
            LiveDeviceCallbackError::UnknownRequest {
                family: "9p",
                epoch: 0,
                request_id,
            },
        )?;
        let inbound = self.ninep_rings.inbound.ninep_inbound();
        let mut completion = NinePOutput { output };
        match handle_9p_poll_callback(
            &self.ninep,
            &mut self.freeze,
            slot,
            &inbound,
            &mut completion,
            current_icount,
            pending.token,
        )
        .map_err(|source| LiveDeviceCallbackError::NineP { source })?
        {
            NinePPoll::NotReady { token } => {
                self.ninep_tokens.insert(
                    request_id,
                    PendingNinePRequest {
                        token,
                        response_capacity: pending.response_capacity,
                    },
                );
                Ok(QEMU_PLUGIN_NINEP_POLL_PENDING)
            }
            NinePPoll::Completed { response, .. } => i64::try_from(response.payload().len())
                .map_err(|_error| LiveDeviceCallbackError::ResponseLengthOverflow {
                    family: "9p",
                    len: response.payload().len(),
                }),
        }
    }

    fn finish_ninep_burst(&mut self, slot: &NodeSlot) -> Result<(), LiveDeviceCallbackError> {
        handle_9p_burst_done_callback(&self.ninep, &mut self.freeze, slot)
            .map(|_state| ())
            .map_err(|source| LiveDeviceCallbackError::NineP { source })
    }
}

const fn block_error_errno(error: BlockResponseErrorCode) -> i64 {
    match error {
        BlockResponseErrorCode::Offline => 123,
        BlockResponseErrorCode::ReadOnly => 30,
        BlockResponseErrorCode::InvalidRange => 22,
        BlockResponseErrorCode::Busy => 16,
        BlockResponseErrorCode::Timeout => 110,
        BlockResponseErrorCode::MediumError | BlockResponseErrorCode::IoError => 5,
        BlockResponseErrorCode::IntegrityError => 84,
        BlockResponseErrorCode::NoSpace => 28,
        BlockResponseErrorCode::NotFound => 2,
        BlockResponseErrorCode::Stale => 116,
    }
}

impl StableDirectedRingHandle {
    fn ring_parts(&self) -> (&RingHeader, &[FrameEntry]) {
        // SAFETY: setup owns the validated mapping for the process lifetime and
        // this adapter's outer mutex serializes all callback-side access.
        unsafe {
            (
                self.header.as_ref(),
                core::slice::from_raw_parts(self.entries.as_ptr(), self.entry_count),
            )
        }
    }

    fn ring_parts_mut(&mut self) -> (&RingHeader, &mut [FrameEntry]) {
        // SAFETY: each fixed outbound ring has exactly one plugin producer and
        // the outer device mutex rejects callback re-entry before this borrow.
        unsafe {
            (
                self.header.as_ref(),
                core::slice::from_raw_parts_mut(self.entries.as_ptr(), self.entry_count),
            )
        }
    }

    fn block_outbound(&mut self) -> BlockOutboundRing<'_> {
        let descriptor = self.descriptor;
        let (header, entries) = self.ring_parts_mut();
        BlockOutboundRing::new(
            descriptor.index,
            descriptor.src_slot,
            descriptor.dst_slot,
            header,
            entries,
        )
    }

    fn block_inbound(&self) -> BlockInboundRing<'_> {
        let (header, entries) = self.ring_parts();
        BlockInboundRing::new(
            self.descriptor.index,
            self.descriptor.src_slot,
            self.descriptor.dst_slot,
            header,
            entries,
        )
    }

    fn ninep_outbound(&mut self) -> NinePOutboundRing<'_> {
        let descriptor = self.descriptor;
        let (header, entries) = self.ring_parts_mut();
        NinePOutboundRing::new(
            descriptor.index,
            descriptor.src_slot,
            descriptor.dst_slot,
            header,
            entries,
        )
    }

    fn ninep_inbound(&self) -> NinePInboundRing<'_> {
        let (header, entries) = self.ring_parts();
        NinePInboundRing::new(
            self.descriptor.index,
            self.descriptor.src_slot,
            self.descriptor.dst_slot,
            header,
            entries,
        )
    }
}

struct BlockOutput<'a> {
    output: &'a mut [u8],
}

impl BlockGuestCompletion for BlockOutput<'_> {
    fn complete_block_response(
        &mut self,
        response: &BlockResponse,
    ) -> Result<(), BlockGuestCompletionError> {
        if response.status() == BlockResponseStatus::Error {
            return Ok(());
        }
        if response.payload().len() > self.output.len() {
            return Err(BlockGuestCompletionError::new(format!(
                "response length {} exceeds QEMU capacity {}",
                response.payload().len(),
                self.output.len()
            )));
        }
        self.output[..response.payload().len()].copy_from_slice(response.payload());
        Ok(())
    }
}

struct NinePOutput<'a> {
    output: &'a mut [u8],
}

impl NinePGuestCompletion for NinePOutput<'_> {
    fn complete_9p_response(
        &mut self,
        response: &NinePResponse,
    ) -> Result<(), NinePGuestCompletionError> {
        if response.payload().len() > self.output.len() {
            return Err(NinePGuestCompletionError::new(format!(
                "response length {} exceeds QEMU capacity {}",
                response.payload().len(),
                self.output.len()
            )));
        }
        self.output[..response.payload().len()].copy_from_slice(response.payload());
        Ok(())
    }
}

fn block_request(
    operation: u32,
    offset: u64,
    data: Option<&[u8]>,
    len: usize,
) -> Result<BlockRequest, LiveDeviceCallbackError> {
    match operation {
        0 => {
            if data.is_some() {
                return Err(LiveDeviceCallbackError::UnexpectedPayloadPointer {
                    family: "block read",
                    len,
                });
            }
            let count = u32::try_from(len).map_err(|_error| {
                LiveDeviceCallbackError::RequestLengthOverflow {
                    family: "block read",
                    len,
                }
            })?;
            Ok(BlockRequest::read(offset, count))
        }
        1 => {
            let payload = data.ok_or(LiveDeviceCallbackError::NullPayload {
                family: "block write",
                len,
            })?;
            if payload.len() != len {
                return Err(LiveDeviceCallbackError::RequestLengthMismatch {
                    family: "block write",
                    declared: len,
                    observed: payload.len(),
                });
            }
            BlockRequest::write(offset, payload.to_vec())
                .map_err(|source| LiveDeviceCallbackError::BlockWire { source })
        }
        2 => {
            if data.is_some() || len != 0 || offset != 0 {
                return Err(LiveDeviceCallbackError::MalformedFlush {
                    offset,
                    len,
                    has_payload: data.is_some(),
                });
            }
            Ok(BlockRequest::flush())
        }
        3 => {
            if data.is_some() {
                return Err(LiveDeviceCallbackError::UnexpectedPayloadPointer {
                    family: "block discard",
                    len,
                });
            }
            let count = u32::try_from(len).map_err(|_error| {
                LiveDeviceCallbackError::RequestLengthOverflow {
                    family: "block discard",
                    len,
                }
            })?;
            Ok(BlockRequest::discard(offset, count))
        }
        operation => Err(LiveDeviceCallbackError::UnknownBlockOperation { operation }),
    }
}

impl LiveVcpuTimeCallbackState {
    fn lock_devices(
        &self,
    ) -> Result<MutexGuard<'_, LiveDeviceCallbackState>, LiveVcpuTimeCallbackError> {
        let devices = self.devices.as_ref().ok_or_else(|| {
            LiveVcpuTimeCallbackError::live_device(LiveDeviceCallbackError::StateUnavailable)
        })?;
        match devices.try_lock() {
            Ok(devices) => Ok(devices),
            Err(TryLockError::WouldBlock) => Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::CallbackReentered,
            )),
            Err(TryLockError::Poisoned(_error)) => Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::StatePoisoned,
            )),
        }
    }

    fn block_submit(
        &self,
        epoch: u64,
        request_id: u32,
        operation: u32,
        offset: u64,
        data: Option<&[u8]>,
        len: usize,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let current_icount = self.device_callback_icount()?;
        self.lock_devices()?
            .submit_block(
                self.slot.get(),
                current_icount,
                epoch,
                request_id,
                operation,
                offset,
                data,
                len,
            )
            .map_err(LiveVcpuTimeCallbackError::live_device)?;
        // The submit callback has release-published `device_io_active` and the
        // request frame. Leave the active TCG reservation now so the sim loop
        // re-reads max-advance and freezes at this exact request boundary until
        // the host pins the deterministic completion deadline.
        (self.force_vcpu_exit)();
        Ok(())
    }

    fn block_poll(
        &self,
        epoch: u64,
        request_id: u32,
        output: &mut [u8],
    ) -> Result<i64, LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending() {
            return Ok(QEMU_PLUGIN_BLOCK_POLL_PENDING);
        }
        let current_icount = self.callback_current_icount()?;
        self.lock_devices()?
            .poll_block(self.slot.get(), current_icount, epoch, request_id, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn block_event_poll(&self, output: &mut [u8]) -> Result<i64, LiveVcpuTimeCallbackError> {
        // A wake carrying a transport event is edge-triggered. When it races
        // QEMU's queued idle-advance completion, deferring the poll would lose
        // the only wake and strand the event in the inbound ring. Device events
        // belong to the already-authorized advance target, just like requests
        // dispatched from the same main-loop timer slice.
        let current_icount = self.device_callback_icount()?;
        self.lock_devices()?
            .poll_block_event(self.slot.get(), current_icount, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn block_event_commit(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        self.lock_devices()?
            .commit_block_event()
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn block_transport_save(&self, output: &mut [u8]) -> Result<usize, LiveVcpuTimeCallbackError> {
        self.lock_devices()?
            .save_block_transport(output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn block_transport_restore(
        &self,
        encoded: &[u8],
        qemu_epoch: u64,
        qemu_next_request_id: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.lock_devices()?
            .restore_block_transport(encoded, qemu_epoch, qemu_next_request_id)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn ninep_burst_start(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        self.lock_devices()?
            .begin_ninep_burst(self.slot.get())
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn ninep_submit(
        &self,
        request_id: u32,
        payload: &[u8],
        response_capacity: usize,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let current_icount = self.device_callback_icount()?;
        self.lock_devices()?
            .submit_ninep(
                self.slot.get(),
                current_icount,
                request_id,
                payload,
                response_capacity,
            )
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn ninep_poll(
        &self,
        request_id: u32,
        output: &mut [u8],
    ) -> Result<i64, LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending() {
            return Ok(QEMU_PLUGIN_NINEP_POLL_PENDING);
        }
        let current_icount = self.callback_current_icount()?;
        self.lock_devices()?
            .poll_ninep(self.slot.get(), current_icount, request_id, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn ninep_burst_done(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        // Completion polling can finish from QEMU's main loop while an idle
        // advance is still being retired. Burst-done only releases the existing
        // device-I/O hold; it neither submits work nor observes guest time, so
        // it must remain legal at that boundary.
        self.lock_devices()?
            .finish_ninep_burst(self.slot.get())
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the QEMU accelerator ABI has fixed fields"
    )]
    fn accelerator_submit(
        &self,
        sequence: u64,
        device_id: [u8; 32],
        class_id: u16,
        job_kind: u16,
        queue_id: u16,
        service_units: u64,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let current_icount = self.device_callback_icount()?;
        self.lock_devices()?
            .submit_accelerator(
                self.slot.get(),
                current_icount,
                sequence,
                device_id,
                class_id,
                job_kind,
                queue_id,
                service_units,
                input,
                output_capacity,
            )
            .map_err(LiveVcpuTimeCallbackError::live_device)?;
        (self.force_vcpu_exit)();
        Ok(())
    }

    fn accelerator_poll(
        &self,
        sequence: u64,
        output: &mut [u8],
    ) -> Result<(u16, i64), LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending() {
            return Ok((0, QEMU_PLUGIN_ACCELERATOR_POLL_PENDING));
        }
        self.lock_devices()?
            .poll_accelerator(self.slot.get(), sequence, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the QEMU accelerator ABI has fixed fields"
)]
pub(super) extern "C" fn crucible_qemu_plugin_live_accelerator_submit_cb(
    sequence: u64,
    device_id: *const u8,
    class_id: u16,
    job_kind: u16,
    queue_id: u16,
    service_units: u64,
    data: *const u8,
    len: usize,
    output_capacity: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let Some(device_id) = std::ptr::NonNull::new(device_id.cast_mut()) else {
        return -1;
    };
    // SAFETY: QEMU supplies a readable fixed 32-byte identity for this call.
    let identity = unsafe { core::slice::from_raw_parts(device_id.as_ptr(), 32) };
    let mut identity_bytes = [0_u8; 32];
    identity_bytes.copy_from_slice(identity);
    // SAFETY: QEMU keeps the input readable for `len` bytes for this call.
    let input = unsafe { input_payload(data, len) }
        .ok_or(LiveDeviceCallbackError::NullPayload {
            family: "accelerator",
            len,
        })
        .unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    match state.accelerator_submit(
        sequence,
        identity_bytes,
        class_id,
        job_kind,
        queue_id,
        service_units,
        input,
        output_capacity,
    ) {
        Ok(()) => 0,
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_accelerator_restore_cb(
    sequence: u64,
    device_id: *const u8,
    _class_id: u16,
    _job_kind: u16,
    _queue_id: u16,
    _service_units: u64,
    output_capacity: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let Some(device_id) = std::ptr::NonNull::new(device_id.cast_mut()) else {
        return -1;
    };
    // SAFETY: QEMU supplies a readable fixed identity for this call.
    let identity = unsafe { core::slice::from_raw_parts(device_id.as_ptr(), 32) };
    let mut identity_bytes = [0_u8; 32];
    identity_bytes.copy_from_slice(identity);
    let current_icount = match state.callback_current_icount() {
        Ok(value) => value,
        Err(error) => abort_live_callback(error),
    };
    let mut devices = match state.lock_devices() {
        Ok(value) => value,
        Err(error) => abort_live_callback(error),
    };
    if devices.accelerator_pending.contains_key(&sequence) {
        return 0;
    }
    let token = match devices
        .freeze
        .begin_independent_submit(state.slot.get(), current_icount)
    {
        Ok(value) => value,
        Err(source) => abort_live_callback(LiveVcpuTimeCallbackError::live_device(
            LiveDeviceCallbackError::AcceleratorFreeze { source },
        )),
    };
    devices.accelerator_pending.insert(
        sequence,
        PendingAcceleratorRequest {
            token,
            device_id: identity_bytes,
            output_capacity,
        },
    );
    0
}

pub(super) extern "C" fn crucible_qemu_plugin_live_accelerator_poll_cb(
    sequence: u64,
    status: *mut u16,
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let Some(mut status) = std::ptr::NonNull::new(status) else {
        return -1;
    };
    // SAFETY: QEMU grants exclusive output access for this callback.
    let output =
        unsafe { output_buffer(output, capacity, "accelerator") }.unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    match state.accelerator_poll(sequence, output) {
        Ok((completion_status, len)) => {
            // SAFETY: QEMU supplies a writable status word for this callback.
            unsafe { *status.as_mut() = completion_status };
            len
        }
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_accelerator_wait_cb(
    _sequence: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    (state.force_vcpu_exit)();
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_submit_cb(
    epoch: u64,
    request_id: u32,
    operation: u32,
    offset: u64,
    data: *const u8,
    len: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU owns the callback input and keeps it readable for `len`
    // bytes until this callback returns.
    let data = unsafe { input_payload(data, len) };
    if let Err(error) = state.block_submit(epoch, request_id, operation, offset, data, len) {
        abort_live_callback(error);
    }
    0
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_poll_cb(
    epoch: u64,
    request_id: u32,
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU grants this callback exclusive access to the output buffer
    // for `capacity` bytes until the callback returns.
    let output = unsafe { output_buffer(output, capacity, "block") }.unwrap_or_else(|source| {
        abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
    });
    match state.block_poll(epoch, request_id, output) {
        Ok(result) => result,
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_event_poll_cb(
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU grants this callback exclusive access to the output buffer
    // for `capacity` bytes until this callback returns.
    let output =
        unsafe { output_buffer(output, capacity, "block event") }.unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    match state.block_event_poll(output) {
        Ok(result) => result,
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_event_commit_cb(
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    match state.block_event_commit() {
        Ok(()) => 0,
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_transport_save_cb(
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU grants exclusive writable access for `capacity` bytes. A
    // null pointer is valid only for the zero-capacity size query.
    let output = unsafe { output_buffer(output, capacity, "block transport continuation") }
        .unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    match state.block_transport_save(output) {
        Ok(len) => i64::try_from(len).unwrap_or_else(|_error| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::ResponseLengthOverflow {
                    family: "block transport continuation",
                    len,
                },
            ))
        }),
        Err(LiveVcpuTimeCallbackError::LiveDevice { source })
            if matches!(
                source.as_ref(),
                LiveDeviceCallbackError::TransportContinuationBusy { .. }
            ) =>
        {
            /*
             * A busy continuation is an expected migration rejection.  The
             * QEMU ABI interprets a negative length as pre-save failure and
             * leaves the source VM alive so its in-flight I/O can finish.
             */
            QEMU_PLUGIN_BLOCK_TRANSPORT_SAVE_BUSY
        }
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_transport_restore_cb(
    input: *const u8,
    len: usize,
    qemu_epoch: u64,
    qemu_next_request_id: u32,
    userdata: *mut c_void,
) -> c_int {
    let Some(state) = std::ptr::NonNull::new(userdata.cast::<LiveVcpuTimeCallbackState>()) else {
        return -1;
    };
    // SAFETY: the registrar passes only the pinned live callback allocation
    // retained by `OwnedCallbackRuntimeState` for the QEMU process lifetime.
    let state = unsafe { state.as_ref() };
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU keeps this VMState-owned input readable for `len` bytes for
    // the duration of the callback.
    let Some(input) = (unsafe { input_payload(input, len) }) else {
        return -1;
    };
    match state.block_transport_restore(input, qemu_epoch, qemu_next_request_id) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("crucible-qemu-plugin: rejected block transport restore: {error}");
            -1
        }
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_ninep_burst_start_cb(userdata: *mut c_void) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.ninep_burst_start() {
        abort_live_callback(error);
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_ninep_submit_cb(
    request_id: u32,
    data: *const u8,
    len: usize,
    response_capacity: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU owns the callback input and keeps it readable for `len`
    // bytes until this callback returns.
    let payload = unsafe { input_payload(data, len) }
        .ok_or(LiveDeviceCallbackError::NullPayload { family: "9p", len })
        .unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    if let Err(error) = state.ninep_submit(request_id, payload, response_capacity) {
        abort_live_callback(error);
    }
    0
}

pub(super) extern "C" fn crucible_qemu_plugin_live_ninep_poll_cb(
    request_id: u32,
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    // SAFETY: QEMU grants this callback exclusive access to the output buffer
    // for `capacity` bytes until the callback returns.
    let output = unsafe { output_buffer(output, capacity, "9p") }.unwrap_or_else(|source| {
        abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
    });
    match state.ninep_poll(request_id, output) {
        Ok(result) => result,
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_ninep_burst_done_cb(userdata: *mut c_void) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.ninep_burst_done() {
        abort_live_callback(error);
    }
}

/// Borrows one QEMU-owned callback input payload.
///
/// # Safety
///
/// A non-null `data` must identify `len` readable bytes that remain live and
/// immutable for the returned borrow.
unsafe fn input_payload<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        return None;
    }
    // SAFETY: QEMU keeps callback input bytes readable until the callback
    // returns; the non-null pointer is paired with its exact ABI length.
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

/// Borrows one QEMU-owned callback output buffer.
///
/// # Safety
///
/// A non-null `output` must identify `capacity` writable bytes to which the
/// caller has exclusive access for the returned borrow.
unsafe fn output_buffer<'a>(
    output: *mut u8,
    capacity: usize,
    family: &'static str,
) -> Result<&'a mut [u8], LiveDeviceCallbackError> {
    if output.is_null() {
        if capacity == 0 {
            return Ok(&mut []);
        }
        return Err(LiveDeviceCallbackError::NullOutput { family, capacity });
    }
    // SAFETY: QEMU gives the poll callback exclusive writable access to this
    // non-null output buffer for `capacity` bytes until the callback returns.
    Ok(unsafe { core::slice::from_raw_parts_mut(output, capacity) })
}

/// A live block or 9p callback registration/dispatch error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LiveDeviceCallbackError {
    /// An accelerator shared-memory operation failed.
    #[error("accelerator shared-memory operation failed: {source}")]
    AcceleratorRing {
        /// Underlying SPSC error.
        source: crucible_shmem::SpscRingError,
    },
    /// An accelerator record was not canonical.
    #[error("accelerator record is invalid: {source}")]
    AcceleratorEntry {
        /// Underlying fixed-record error.
        source: crucible_shmem::AcceleratorEntryError,
    },
    /// Accelerator device-I/O freeze accounting failed.
    #[error("accelerator device-I/O freeze failed: {source}")]
    AcceleratorFreeze {
        /// Underlying freeze-state error.
        source: crate::DeviceIoFreezeError,
    },
    /// The accelerator class was outside the closed public enum.
    #[error("unknown accelerator class {class_id}")]
    UnknownAcceleratorClass {
        /// Rejected class number.
        class_id: u16,
    },
    /// A request sequence was reused before its lifecycle ended.
    #[error("duplicate accelerator sequence {sequence}")]
    DuplicateAcceleratorSequence {
        /// Reused publication sequence.
        sequence: u64,
    },
    /// A completion did not correspond to a submitted request.
    #[error("unknown accelerator sequence {sequence}")]
    UnknownAcceleratorSequence {
        /// Completion sequence without a pending request.
        sequence: u64,
    },
    /// A completion's envelope disagreed with the submitted request.
    #[error("invalid accelerator completion for sequence {sequence}")]
    InvalidAcceleratorCompletion {
        /// Completion sequence whose envelope was invalid.
        sequence: u64,
    },
    /// A completion exceeded QEMU's guest-provided output buffer.
    #[error("accelerator completion {sequence} length {len} exceeds capacity {capacity}")]
    AcceleratorOutputTooLarge {
        /// Completion publication sequence.
        sequence: u64,
        /// Returned output length.
        len: usize,
        /// Available guest buffer capacity.
        capacity: usize,
    },
    /// Registration-fixed block state or callback handling failed.
    #[error("live block callback failed: {source}")]
    Block {
        /// Underlying safe block callback error.
        source: BlockIoError,
    },
    /// A raw block request could not be converted to the safe wire model.
    #[error("live block request conversion failed: {source}")]
    BlockWire {
        /// Underlying block wire error.
        source: BlockWireError,
    },
    /// A transport reset appeared where the driver expected a primary result.
    #[error("block request {request_id} returned reset as its primary completion")]
    UnexpectedBlockResetPrimary {
        /// Request whose primary completion was invalid.
        request_id: u32,
    },
    /// A duplicate-only status appeared in a primary request poll.
    #[error("block request {request_id} returned a duplicate-only primary completion")]
    UnexpectedBlockDuplicatePrimary {
        /// Request whose primary completion was invalid.
        request_id: u32,
    },
    /// QEMU attempted to commit without first preparing a block event.
    #[error("no block transport event is prepared for commit")]
    NoPreparedBlockEvent,
    /// VMState attempted to save or restore while transport state was in flight.
    #[error(
        "block transport continuation is busy: {block_tokens} requests, {retry_authorizations} retry authorizations, prepared_event={prepared_event}"
    )]
    TransportContinuationBusy {
        /// Submitted requests not yet terminally polled.
        block_tokens: usize,
        /// Preserve-ID retry authorizations not yet resubmitted.
        retry_authorizations: usize,
        /// Whether an event was prepared but not committed.
        prepared_event: bool,
    },
    /// Registration-fixed 9p state or callback handling failed.
    #[error("live 9p callback failed: {source}")]
    NineP {
        /// Underlying safe 9p callback error.
        source: NinePIoError,
    },
    /// The live device state was not installed before callback dispatch.
    #[error("live block/9p callback state is unavailable")]
    StateUnavailable,
    /// A device callback re-entered while mutable callback state was borrowed.
    #[error("live block/9p callback state was re-entered")]
    CallbackReentered,
    /// A previous callback panic poisoned the device state.
    #[error("live block/9p callback state is poisoned")]
    StatePoisoned,
    /// QEMU and the plugin's fixed request sequence disagreed.
    #[error(
        "live {family} request identity mismatch: QEMU supplied ({qemu_epoch}, {qemu_request_id}), plugin expected ({plugin_epoch}, {plugin_request_id})"
    )]
    RequestIdMismatch {
        /// Device callback family.
        family: &'static str,
        /// Driver-supplied request epoch.
        qemu_epoch: u64,
        /// Driver-supplied request id.
        qemu_request_id: u32,
        /// Plugin's current request epoch.
        plugin_epoch: u64,
        /// Plugin's next fixed request id.
        plugin_request_id: u32,
    },
    /// QEMU polled a request that was not retained after submit.
    #[error("live {family} poll named unknown request ({epoch}, {request_id})")]
    UnknownRequest {
        /// Device callback family.
        family: &'static str,
        /// Unknown request epoch.
        epoch: u64,
        /// Unknown request id.
        request_id: u32,
    },
    /// QEMU supplied a null pointer for a nonempty payload.
    #[error("live {family} payload is null for nonzero length {len}")]
    NullPayload {
        /// Device callback family.
        family: &'static str,
        /// Claimed payload length.
        len: usize,
    },
    /// QEMU supplied a null writable buffer with nonzero capacity.
    #[error("live {family} output is null for nonzero capacity {capacity}")]
    NullOutput {
        /// Device callback family.
        family: &'static str,
        /// Claimed writable capacity.
        capacity: usize,
    },
    /// A payload pointer was present for an operation that forbids one.
    #[error("live {family} unexpectedly supplied a payload pointer for length {len}")]
    UnexpectedPayloadPointer {
        /// Device operation.
        family: &'static str,
        /// Supplied request length.
        len: usize,
    },
    /// A request length cannot fit the deterministic wire format.
    #[error("live {family} request length {len} cannot fit the wire format")]
    RequestLengthOverflow {
        /// Device operation.
        family: &'static str,
        /// Unrepresentable length.
        len: usize,
    },
    /// Pointer-derived and ABI-declared request lengths disagreed.
    #[error("live {family} request length mismatch: declared {declared}, observed {observed}")]
    RequestLengthMismatch {
        /// Device operation.
        family: &'static str,
        /// ABI length.
        declared: usize,
        /// Borrowed slice length.
        observed: usize,
    },
    /// QEMU supplied an unknown block operation constant.
    #[error("live block callback supplied unknown operation {operation}")]
    UnknownBlockOperation {
        /// Unknown operation value.
        operation: u32,
    },
    /// QEMU supplied operation-inconsistent flush fields.
    #[error(
        "live block flush is malformed: offset={offset}, len={len}, payload_pointer={has_payload}"
    )]
    MalformedFlush {
        /// Unexpected offset.
        offset: u64,
        /// Unexpected payload length.
        len: usize,
        /// Whether a non-null payload was supplied.
        has_payload: bool,
    },
    /// A response length cannot fit QEMU's signed poll return type.
    #[error("live {family} response length {len} cannot fit i64")]
    ResponseLengthOverflow {
        /// Device callback family.
        family: &'static str,
        /// Unrepresentable response length.
        len: usize,
    },
    /// QEMU supplied a buffer too small for a fixed response envelope.
    #[error("live {family} buffer has {observed} bytes but requires at least {required}")]
    ResponseBufferTooSmall {
        /// Device callback family.
        family: &'static str,
        /// Minimum fixed capacity.
        required: usize,
        /// Supplied capacity.
        observed: usize,
    },
    /// QEMU changed a retained 9p response capacity before polling.
    #[error(
        "live {family} request {request_id} response capacity changed from {registered} to {observed}"
    )]
    ResponseCapacityChanged {
        /// Device callback family.
        family: &'static str,
        /// Request id whose capacity changed.
        request_id: u32,
        /// Submit-time response capacity.
        registered: usize,
        /// Poll-time output capacity.
        observed: usize,
    },
}

#[cfg(test)]
mod tests;
