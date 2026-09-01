//! The block sub-node: an [`IoSubNode`] over a base image and CoW overlay.
//!
//! This module owns [`BlockDevice`], which implements the COMPUTE half of the
//! uniform lifecycle for block I/O. It decodes a [`BlockRequest`] from the
//! request payload, serves it against the [`BaseImage`] + [`CowOverlay`]
//! ([IO-5], [IO-6]), and re-encodes a [`BlockResponse`] as the response payload.
//! The deterministic completion time is supplied by [`BlockLatency`] and applied
//! by the [`IoCore`] the device composes ([IO-10], [IO-22]).
//!
//! It also owns [`BlockSnapshot`], the device half of a `MaterializedState`
//! contribution: the overlay delta (dirty pages only), the device RNG position
//! cursor, the active fault table, the in-flight responses, the base hash, and
//! the device length — **never** the base image bytes ([IO-11], [TEMP-9]).
//! [`BlockDevice::restore`]
//! stacks the delta over a parent overlay and re-arms the in-flight queue, and
//! [`BlockDevice::materialize`] hands off a standalone raw image ([IO-12]).
//!
//! ```text
//! request payload  = BlockRequest::encode()   (rides the SLOT_BLK_IO ring)
//! compute(req):
//!   decode -> serve over overlay/base -> BlockResponse
//!   malformed bytes / out-of-range    -> error-status BlockResponse (never panic)
//! response payload = BlockResponse::encode()
//! delivery_icount  = ceil(vt(request_icount) + BlockLatency::latency_ns)
//! ```

use crucible_shmem::{FrameEntry, NodeSlot, RingHeader, icount_to_virtual_ns};

use crate::error::DeviceError;
use crate::request::{ComputedResponse, LatencyModel, Request, Response, ResponseStatus};
use crate::subnode::{IoCore, IoSubNode, ShmemDeliveryResult, ShmemInboxProcess};

use super::codec::{
    BlockErrorCode, BlockOp, BlockRequest, BlockRequestIdentity, BlockResponse, RESPONSE_HEADER_LEN,
};
use super::codec::{BlockStatus, BlockTransportReset, BlockTransportUndelivered};
use super::fault::keyed_discard_bytes;
use super::fault::{
    BlockCompletionDurability, BlockDeliveryOpportunity, BlockDiscardSemantics,
    BlockDurabilityConfig, BlockExecutionOpportunity, BlockFaultState,
    BlockPersistenceMediaOutcome, BlockPersistenceOpportunity, BlockRequestPersistenceOpportunity,
    BlockRetainedRelease, BlockRetainedReleaseOutcome, BlockStorageOutcome,
    ResolvedBlockControllerTransition, ResolvedBlockDeliveryDirective,
    ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective, ResolvedBlockRequestPersistenceDirective,
};
use super::overlay::{BaseImage, CowOverlay};
use super::service::BlockServiceCompletion;

pub use snapshot::{BlockSnapshot, BlockSnapshotCodecError, MAX_BLOCK_SNAPSHOT_BYTES};

/// The largest read payload that fits one shmem frame alongside its header.
///
/// A [`BlockResponse`] rides a single SPSC frame whose data field is
/// [`crucible_shmem::MAX_FRAME_DATA`] bytes ([SHM-13]); the read payload must
/// leave room for the fixed [`RESPONSE_HEADER_LEN`]-byte response header. A read
/// whose `count` exceeds this is rejected with an error status ([IO-8]) rather
/// than emitting an un-transportable frame. The bound is derived from the
/// `crucible-shmem` constant, never hardcoded, so it tracks the ABI.
pub const MAX_READ_BYTES: usize = crucible_shmem::MAX_FRAME_DATA - RESPONSE_HEADER_LEN;

/// The deterministic completion-latency model for the block device.
///
/// Latency is `base_op_ns(op) + per_byte_ns * count` — a pure function of the
/// operation and the byte count and the device's configured parameters, with no
/// host-timing term ([IO-10], [IO-22]). The per-op floors let read, write, and
/// flush differ. All arithmetic saturates so an adversarial `count` cannot
/// panic; no floating point is used ([IO-24]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockLatency {
    /// Fixed latency floor for a read, in virtual nanoseconds.
    pub read_base_ns: u64,
    /// Fixed latency floor for a write, in virtual nanoseconds.
    pub write_base_ns: u64,
    /// Fixed latency for a flush, in virtual nanoseconds.
    pub flush_ns: u64,
    /// Fixed latency for a get-length, in virtual nanoseconds.
    pub get_length_ns: u64,
    /// Per-byte transfer cost added to a read or write, in virtual nanoseconds.
    pub per_byte_ns: u64,
}

impl BlockLatency {
    /// Creates a latency model from explicit per-op and per-byte parameters.
    #[must_use]
    pub fn new(
        read_base_ns: u64,
        write_base_ns: u64,
        flush_ns: u64,
        get_length_ns: u64,
        per_byte_ns: u64,
    ) -> Self {
        Self {
            read_base_ns,
            write_base_ns,
            flush_ns,
            get_length_ns,
            per_byte_ns,
        }
    }

    /// Returns the modeled latency for an operation and byte count.
    ///
    /// Saturating throughout so a hostile `count` yields `u64::MAX` rather than
    /// overflowing.
    #[must_use]
    pub fn latency_for(&self, op: BlockOp, count: u32) -> u64 {
        let variable = self.per_byte_ns.saturating_mul(u64::from(count));
        match op {
            BlockOp::Read => self.read_base_ns.saturating_add(variable),
            BlockOp::Write => self.write_base_ns.saturating_add(variable),
            BlockOp::Flush => self.flush_ns,
            BlockOp::GetLength => self.get_length_ns,
            BlockOp::Discard => self.write_base_ns.saturating_add(variable),
        }
    }
}

impl Default for BlockLatency {
    /// A modest default model: read/write floors with a small per-byte cost.
    fn default() -> Self {
        Self {
            read_base_ns: 1_000,
            write_base_ns: 1_500,
            flush_ns: 500,
            get_length_ns: 100,
            per_byte_ns: 1,
        }
    }
}

impl LatencyModel for BlockLatency {
    /// Derives latency from the encoded [`BlockRequest`] in the payload.
    ///
    /// A request payload that fails to decode is modeled with the read floor so
    /// the error response still completes at a deterministic, host-independent
    /// icount; the byte count for that case is zero.
    fn latency_ns(&self, request: &Request) -> u64 {
        match BlockRequest::decode(&request.payload) {
            Ok(decoded) => self.latency_for(decoded.op, decoded.count),
            Err(_) => self.read_base_ns,
        }
    }
}

/// A block device sub-node over a read-only base image and a CoW overlay.
///
/// Composes an [`IoCore`] (clock, rings, in-flight queue) with the device state
/// (base image, overlay, latency model, and exact storage continuation). Drive it with
/// [`IoCore`]'s lifecycle methods reached through [`BlockDevice::core_mut`], or
/// the convenience wrappers [`BlockDevice::submit`] / [`BlockDevice::advance_to`]
/// / [`BlockDevice::next_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDevice {
    core: IoCore,
    base: BaseImage,
    overlay: CowOverlay,
    storage_faults: BlockFaultState,
    latency: BlockLatency,
}

struct PreparedBlockTransportReset {
    storage_faults: BlockFaultState,
    inflight: Vec<crate::inflight::PendingResponse>,
    immediate: Vec<Response>,
}

/// Atomically installs a persist-phase write redirected to another device.
///
/// The destination receives the exact request bytes through its own admitted
/// geometry and durability state. The source retains the sole guest completion
/// and executes the request as a locally lost write after both cloned device
/// states commit together. Its completion carries an exact destination
/// durability dependency so the guest cannot observe success before that
/// frontier is acknowledged.
///
/// # Errors
///
/// Returns [`DeviceError`] if the directive is not an external misdirected
/// write for `destination_device`, either staged mutation fails, or the source
/// persistence opportunity is stale. Neither device changes on error.
pub fn install_cross_device_misdirected_persistence(
    source: &mut BlockDevice,
    destination: &mut BlockDevice,
    mut resolved: ResolvedBlockRequestPersistenceDirective,
    destination_device: [u8; 32],
) -> Result<super::fault::BlockExternalDurabilityDependency, DeviceError> {
    let destination_offset = match resolved.directive.write_disposition {
        super::fault::BlockFaultWriteDisposition::Misdirected {
            destination: super::fault::BlockFaultMisdirectionDestination::ExternalDevice(device),
            destination_offset,
        } if device == destination_device => destination_offset,
        _ => {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "cross-device persistence requires its exact external destination",
            });
        }
    };
    if resolved.opportunity.request.op != BlockOp::Write {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "cross-device persistence requires a write request",
        });
    }
    let mut next_source = source.clone();
    let mut next_destination = destination.clone();
    let (destination_durability, destination_frontier) =
        next_destination.storage_faults.apply_external_write(
            &next_destination.base,
            &mut next_destination.overlay,
            resolved.opportunity.request.request_id,
            resolved.directive.request_sequence,
            resolved.opportunity.ready_nanos,
            destination_offset,
            resolved.opportunity.request.data.clone(),
        )?;
    resolved.directive.write_disposition = super::fault::BlockFaultWriteDisposition::Lost;
    let dependency = super::fault::BlockExternalDurabilityDependency {
        destination_device,
        required_durability: destination_durability,
        required_frontier: destination_frontier,
    };
    resolved.directive.external_durability_dependencies = vec![dependency];
    next_source.install_storage_request_persistence_directive(resolved)?;
    *source = next_source;
    *destination = next_destination;
    Ok(dependency)
}

#[path = "device/core.rs"]
mod core;
#[path = "device/external.rs"]
mod external;
#[path = "device/lifecycle.rs"]
mod lifecycle;
#[path = "device/snapshot.rs"]
mod snapshot;
#[path = "device/snapshot_runtime.rs"]
mod snapshot_runtime;

fn block_response_to_uniform_device(response: &BlockResponse) -> Result<Response, DeviceError> {
    let status = if response.status == BlockStatus::Ok {
        ResponseStatus::Ok
    } else {
        ResponseStatus::Error
    };
    Ok(Response::new(
        response.request_id,
        status,
        response.encode().map_err(DeviceError::Codec)?,
    ))
}

fn ceil_nanos_to_valid_icount(target_nanos: u64, shift_bits: u8) -> u64 {
    debug_assert!(shift_bits < 64);
    if shift_bits == 0 {
        return target_nanos;
    }
    let quotient = target_nanos >> shift_bits;
    let mask = (1_u64 << shift_bits) - 1;
    quotient + u64::from(target_nanos & mask != 0)
}

/// The detached COMPUTE view a [`BlockDevice`] hands to [`IoCore::process_inbox`].
///
/// Borrows only the device fields the COMPUTE step touches (base, overlay,
/// latency), sidestepping the `&mut self`-to-both-args borrow conflict. It is
/// the concrete [`IoSubNode`]: every request is decoded, served against the
/// overlay/base, and re-encoded — out-of-range and malformed requests become
/// error-status responses, never panics ([IO-6], [IO-8]).
struct BlockServer<'a> {
    base: &'a BaseImage,
    overlay: &'a mut CowOverlay,
    storage_faults: &'a mut BlockFaultState,
    latency: &'a BlockLatency,
}

impl<'a> IoSubNode for BlockServer<'a> {
    type Latency = BlockLatency;
    type ComputeCheckpoint = (CowOverlay, BlockFaultState);

    fn latency_model(&self) -> &Self::Latency {
        self.latency
    }

    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint {
        (self.overlay.clone(), self.storage_faults.clone())
    }

    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint) {
        *self.overlay = checkpoint.0;
        *self.storage_faults = checkpoint.1;
    }

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        // Decode the wire request from the opaque payload. Hostile bytes yield an
        // error-status response keyed to the uniform request id ([IO-8]); the
        // device never panics or reads out of bounds.
        match BlockRequest::decode(&request.payload) {
            Ok(decoded) => self.storage_faults.execute(
                self.base,
                self.overlay,
                &decoded,
                request.request_icount,
            ),
            Err(_) => {
                let wire = BlockResponse::error(request.request_id, BlockErrorCode::IoError);
                let encoded = wire.encode().map_err(DeviceError::Codec)?;
                Ok(ComputedResponse::primary(Response::new(
                    request.request_id,
                    ResponseStatus::Error,
                    encoded,
                )))
            }
        }
    }
}
