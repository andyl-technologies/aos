//! Live block and 9p adapters for the QEMU callback ABI.
//!
//! The adapters retain request tokens across QEMU's submit/poll split, bind the
//! fixed executor rings selected from setup shared memory, and share one
//! device-I/O freeze state so block requests and 9p bursts cannot clear each
//! other's virtual-time hold.

use std::collections::BTreeMap;
use std::os::raw::{c_int, c_void};
use std::sync::{MutexGuard, TryLockError};

use crucible_shmem::{FrameEntry, NodeSlot, RingHeader};
use thiserror::Error;

use crate::{
    BlockGuestCompletion, BlockGuestCompletionError, BlockInboundRing, BlockIoError,
    BlockOutboundRing, BlockPoll, BlockRequest, BlockRequestToken, BlockResponse,
    BlockResponseStatus, BlockWireError, NinePGuestCompletion, NinePGuestCompletionError,
    NinePInboundRing, NinePIoError, NinePOutboundRing, NinePPoll, NinePRequest, NinePRequestToken,
    NinePResponse, PluginBlockIo, PluginDeviceIoFreeze, PluginNinePIo,
    handle_9p_burst_done_callback, handle_9p_burst_start_callback, handle_9p_poll_callback,
    handle_9p_submit_callback, handle_block_poll_callback, handle_block_submit_callback,
};

use super::{
    LiveDirectedRingPair, LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState,
    StableDirectedRingHandle, abort_live_callback, callback_userdata_or_abort,
};

const QEMU_PLUGIN_BLOCK_POLL_PENDING: i64 = -2;
const QEMU_PLUGIN_NINEP_POLL_PENDING: i64 = -2;

pub(super) struct LiveDeviceCallbackState {
    freeze: PluginDeviceIoFreeze,
    block: PluginBlockIo,
    block_rings: LiveDirectedRingPair,
    block_tokens: BTreeMap<u32, BlockRequestToken>,
    ninep: PluginNinePIo,
    ninep_rings: LiveDirectedRingPair,
    ninep_tokens: BTreeMap<u32, PendingNinePRequest>,
}

struct PendingNinePRequest {
    token: NinePRequestToken,
    response_capacity: usize,
}

impl LiveDeviceCallbackState {
    pub(super) fn new(
        vm_slot: u32,
        block_rings: LiveDirectedRingPair,
        ninep_rings: LiveDirectedRingPair,
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
            ninep,
            ninep_rings,
            ninep_tokens: BTreeMap::new(),
        })
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
        qemu_request_id: u32,
        operation: u32,
        offset: u64,
        data: Option<&[u8]>,
        len: usize,
    ) -> Result<(), LiveDeviceCallbackError> {
        if self.block.next_request_id() != qemu_request_id
            || self.block_tokens.contains_key(&qemu_request_id)
        {
            return Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "block",
                qemu_request_id,
                plugin_request_id: self.block.next_request_id(),
            });
        }
        let request = block_request(operation, offset, data, len)?;
        let mut outbound = self.block_rings.outbound.block_outbound();
        let submit = handle_block_submit_callback(
            &self.block,
            &mut self.freeze,
            slot,
            &mut outbound,
            current_icount,
            &request,
        )
        .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        if submit.request_id() != qemu_request_id {
            return Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "block",
                qemu_request_id,
                plugin_request_id: submit.request_id(),
            });
        }
        self.block_tokens
            .insert(qemu_request_id, submit.into_token());
        Ok(())
    }

    fn poll_block(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        request_id: u32,
        output: &mut [u8],
    ) -> Result<i64, LiveDeviceCallbackError> {
        let token = self.block_tokens.remove(&request_id).ok_or(
            LiveDeviceCallbackError::UnknownRequest {
                family: "block",
                request_id,
            },
        )?;
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
                self.block_tokens.insert(request_id, token);
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
                BlockResponseStatus::Error => Ok(-1),
            },
        }
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
                qemu_request_id,
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
                qemu_request_id,
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
        request_id: u32,
        operation: u32,
        offset: u64,
        data: Option<&[u8]>,
        len: usize,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending()? {
            return Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::CallbackDuringIdleAdvance { family: "block" },
            ));
        }
        let current_icount = self.callback_current_icount()?;
        self.lock_devices()?
            .submit_block(
                self.slot.get(),
                current_icount,
                request_id,
                operation,
                offset,
                data,
                len,
            )
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn block_poll(
        &self,
        request_id: u32,
        output: &mut [u8],
    ) -> Result<i64, LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending()? {
            return Ok(QEMU_PLUGIN_BLOCK_POLL_PENDING);
        }
        let current_icount = self.callback_current_icount()?;
        self.lock_devices()?
            .poll_block(self.slot.get(), current_icount, request_id, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn ninep_burst_start(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending()? {
            return Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::CallbackDuringIdleAdvance { family: "9p" },
            ));
        }
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
        if self.idle_advance_is_pending()? {
            return Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::CallbackDuringIdleAdvance { family: "9p" },
            ));
        }
        let current_icount = self.callback_current_icount()?;
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
        if self.idle_advance_is_pending()? {
            return Ok(QEMU_PLUGIN_NINEP_POLL_PENDING);
        }
        let current_icount = self.callback_current_icount()?;
        self.lock_devices()?
            .poll_ninep(self.slot.get(), current_icount, request_id, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }

    fn ninep_burst_done(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending()? {
            return Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::CallbackDuringIdleAdvance { family: "9p" },
            ));
        }
        self.lock_devices()?
            .finish_ninep_burst(self.slot.get())
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_submit_cb(
    request_id: u32,
    operation: u32,
    offset: u64,
    data: *const u8,
    len: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    // SAFETY: QEMU owns the callback input and keeps it readable for `len`
    // bytes until this callback returns.
    let data = unsafe { input_payload(data, len) };
    if let Err(error) = state.block_submit(request_id, operation, offset, data, len) {
        abort_live_callback(error);
    }
    0
}

pub(super) extern "C" fn crucible_qemu_plugin_live_block_poll_cb(
    request_id: u32,
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    // SAFETY: QEMU grants this callback exclusive access to the output buffer
    // for `capacity` bytes until the callback returns.
    let output = unsafe { output_buffer(output, capacity, "block") }.unwrap_or_else(|source| {
        abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
    });
    match state.block_poll(request_id, output) {
        Ok(result) => result,
        Err(error) => abort_live_callback(error),
    }
}

pub(super) extern "C" fn crucible_qemu_plugin_live_ninep_burst_start_cb(userdata: *mut c_void) {
    let state = callback_userdata_or_abort(userdata);
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
    if let Err(error) = state.ninep_burst_done() {
        abort_live_callback(error);
    }
}

unsafe fn input_payload<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        return None;
    }
    // SAFETY: QEMU keeps callback input bytes readable until the callback
    // returns; the non-null pointer is paired with its exact ABI length.
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

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
    /// A callback ran while an exact idle advance was still pending.
    #[error("live {family} callback ran during a pending idle advance")]
    CallbackDuringIdleAdvance {
        /// Device family that crossed the completion barrier.
        family: &'static str,
    },
    /// QEMU and the plugin's fixed request sequence disagreed.
    #[error(
        "live {family} request id mismatch: QEMU supplied {qemu_request_id}, plugin expected {plugin_request_id}"
    )]
    RequestIdMismatch {
        /// Device callback family.
        family: &'static str,
        /// Driver-supplied request id.
        qemu_request_id: u32,
        /// Plugin's next fixed request id.
        plugin_request_id: u32,
    },
    /// QEMU polled a request that was not retained after submit.
    #[error("live {family} poll named unknown request {request_id}")]
    UnknownRequest {
        /// Device callback family.
        family: &'static str,
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
mod tests {
    use super::*;

    use crucible_shmem::{
        DirectedRing, KIND_VM, MappedDirectedRingMut, RegionConfig, RegionHeader, RegionLayout,
        SLOT_9P_IO, SLOT_BLK_IO, authorize_advance_ceiling,
    };

    #[test]
    fn live_device_adapters_retain_tokens_and_complete_block_and_ninep() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let mut storage = DeviceRingStorage::new();
        let block = storage.block_pair();
        let ninep = storage.ninep_pair();
        let mut devices = LiveDeviceCallbackState::new(0, block, ninep)
            .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

        devices
            .submit_block(&slot, 5, 0, 0, 12, None, 4)
            .unwrap_or_else(|error| panic!("block read should submit: {error}"));
        assert_eq!(storage.block_out_header.write_index(), 1);
        assert_eq!(slot.snapshot().device_io_active, 1);
        let mut block_output = [0_u8; 4];
        assert_eq!(
            devices
                .poll_block(&slot, 5, 0, &mut block_output)
                .unwrap_or_else(|error| panic!("empty block poll should stay pending: {error}")),
            QEMU_PLUGIN_BLOCK_POLL_PENDING
        );
        let block_response = BlockResponse::new(BlockResponseStatus::Ok, 0, b"data".to_vec())
            .encode()
            .unwrap_or_else(|error| panic!("block response should encode: {error}"));
        enqueue_response(
            &storage.block_in_header,
            &mut storage.block_in_entries,
            5,
            SLOT_BLK_IO as u32,
            0,
            &block_response,
        );
        assert_eq!(
            devices
                .poll_block(&slot, 5, 0, &mut block_output)
                .unwrap_or_else(|error| panic!("due block response should complete: {error}")),
            4
        );
        assert_eq!(&block_output, b"data");
        assert_eq!(storage.block_in_header.read_index(), 1);
        assert_eq!(slot.snapshot().device_io_active, 0);

        devices
            .begin_ninep_burst(&slot)
            .unwrap_or_else(|error| panic!("9p burst should start: {error}"));
        devices
            .submit_ninep(&slot, 7, 0, b"request", 8)
            .unwrap_or_else(|error| panic!("9p request should submit: {error}"));
        assert_eq!(storage.ninep_out_header.write_index(), 1);
        enqueue_response(
            &storage.ninep_in_header,
            &mut storage.ninep_in_entries,
            7,
            SLOT_9P_IO as u32,
            0,
            b"response",
        );
        let mut ninep_output = [0_u8; 8];
        assert_eq!(
            devices
                .poll_ninep(&slot, 7, 0, &mut ninep_output)
                .unwrap_or_else(|error| panic!("due 9p response should complete: {error}")),
            8
        );
        assert_eq!(&ninep_output, b"response");
        devices
            .finish_ninep_burst(&slot)
            .unwrap_or_else(|error| panic!("answered 9p burst should finish: {error}"));
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    #[test]
    fn live_device_preflight_rejects_qemu_request_id_drift_without_mutation() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let mut storage = DeviceRingStorage::new();
        let block = storage.block_pair();
        let ninep = storage.ninep_pair();
        let mut devices = LiveDeviceCallbackState::new(0, block, ninep)
            .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

        assert_eq!(
            devices.submit_block(&slot, 5, 3, 0, 0, None, 1),
            Err(LiveDeviceCallbackError::RequestIdMismatch {
                family: "block",
                qemu_request_id: 3,
                plugin_request_id: 0,
            })
        );
        assert_eq!(storage.block_out_header.write_index(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    #[test]
    fn live_device_callback_reentry_is_rejected_before_ring_or_freeze_mutation() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let layout = RegionLayout::for_config(RegionConfig::new(1, 4, 0))
            .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
        let header = RegionHeader::new(layout);
        let deadline = crate::ExactDeadlineReader::require(Some(test_deadline))
            .unwrap_or_else(|error| panic!("test deadline should bind: {error}"));
        let advance = crate::QueuedIdleAdvance::require(Some(test_advance))
            .unwrap_or_else(|error| panic!("test advance should bind: {error}"));
        let mut storage = DeviceRingStorage::new();
        let block = storage.block_pair();
        let ninep = storage.ninep_pair();
        let state = LiveVcpuTimeCallbackState::new(
            61,
            test_icount_raw,
            1,
            0,
            0,
            deadline,
            advance,
            &header,
            &slot,
        )
        .and_then(|state| state.attach_devices(0, block, ninep))
        .unwrap_or_else(|error| panic!("test live state should attach devices: {error}"));
        let devices = state
            .devices
            .as_ref()
            .unwrap_or_else(|| panic!("test device state should exist"));
        let guard = devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        assert_eq!(
            state.block_submit(0, 0, 0, None, 1),
            Err(LiveVcpuTimeCallbackError::live_device(
                LiveDeviceCallbackError::CallbackReentered,
            ))
        );
        drop(guard);
        assert_eq!(storage.block_out_header.write_index(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    extern "C" fn test_deadline() -> i64 {
        -1
    }

    extern "C" fn test_advance(_target: i64) -> c_int {
        0
    }

    extern "C" fn test_icount_raw() -> u64 {
        0
    }

    struct DeviceRingStorage {
        block_out_header: RingHeader,
        block_out_entries: Vec<FrameEntry>,
        block_in_header: RingHeader,
        block_in_entries: Vec<FrameEntry>,
        ninep_out_header: RingHeader,
        ninep_out_entries: Vec<FrameEntry>,
        ninep_in_header: RingHeader,
        ninep_in_entries: Vec<FrameEntry>,
    }

    impl DeviceRingStorage {
        fn new() -> Self {
            Self {
                block_out_header: RingHeader::new(),
                block_out_entries: vec![FrameEntry::default(); 4],
                block_in_header: RingHeader::new(),
                block_in_entries: vec![FrameEntry::default(); 4],
                ninep_out_header: RingHeader::new(),
                ninep_out_entries: vec![FrameEntry::default(); 4],
                ninep_in_header: RingHeader::new(),
                ninep_in_entries: vec![FrameEntry::default(); 4],
            }
        }

        fn block_pair(&mut self) -> LiveDirectedRingPair {
            ring_pair(
                0,
                SLOT_BLK_IO as u32,
                2,
                3,
                &self.block_out_header,
                &mut self.block_out_entries,
                &self.block_in_header,
                &mut self.block_in_entries,
            )
        }

        fn ninep_pair(&mut self) -> LiveDirectedRingPair {
            ring_pair(
                0,
                SLOT_9P_IO as u32,
                4,
                5,
                &self.ninep_out_header,
                &mut self.ninep_out_entries,
                &self.ninep_in_header,
                &mut self.ninep_in_entries,
            )
        }
    }

    // crucible-lint: allow rust-allow -- the fixture spells both directed endpoints and their distinct backing stores.
    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper spells both directed ring endpoints and backing stores"
    )]
    fn ring_pair(
        vm_slot: u32,
        executor_slot: u32,
        outbound_index: u32,
        inbound_index: u32,
        outbound_header: &RingHeader,
        outbound_entries: &mut [FrameEntry],
        inbound_header: &RingHeader,
        inbound_entries: &mut [FrameEntry],
    ) -> LiveDirectedRingPair {
        LiveDirectedRingPair::new(
            MappedDirectedRingMut {
                descriptor: DirectedRing {
                    index: outbound_index,
                    src_slot: vm_slot,
                    dst_slot: executor_slot,
                },
                header: outbound_header,
                entries: outbound_entries,
            },
            MappedDirectedRingMut {
                descriptor: DirectedRing {
                    index: inbound_index,
                    src_slot: executor_slot,
                    dst_slot: vm_slot,
                },
                header: inbound_header,
                entries: inbound_entries,
            },
        )
        .unwrap_or_else(|error| panic!("test ring handles should build: {error}"))
    }

    fn enqueue_response(
        header: &RingHeader,
        entries: &mut [FrameEntry],
        delivery_icount: u64,
        source: u32,
        sequence: u32,
        payload: &[u8],
    ) {
        let frame = FrameEntry::new(delivery_icount, source, sequence, payload)
            .unwrap_or_else(|error| panic!("test response frame should build: {error}"));
        header
            .enqueue(entries, &frame)
            .unwrap_or_else(|error| panic!("test response should enqueue: {error}"));
    }
}
