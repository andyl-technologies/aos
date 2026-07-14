//! Host block-I/O servicer for a live QEMU node's `SLOT_BLK_IO` rings.
//!
//! A live guest with a `crucible-shmem` virtio-blk device issues real block
//! reads and writes (the kernel's partition probe alone issues reads). The
//! `crucible-shmem` QEMU driver places each request as a [`FrameEntry`] on the
//! VM-to-device `SLOT_BLK_IO` ring, and the guest blocks until the matching
//! response frame appears on the device-to-VM ring. Nothing services that ring
//! by default, so the guest stalls on its first block request -- the gap this
//! runtime closes.
//!
//! [`QemuLiveBlockIoServicer`] maps the shared-memory region read-write (an
//! independent `MAP_SHARED` view of the same descriptor the node's channel maps)
//! and composes a deterministic [`BlockDevice`] over a fixed [`BaseImage`]. Each
//! [`QemuLiveBlockIoServicer::service`] call drains newly arrived request frames,
//! COMPUTEs each into an ordered in-flight response at its exact
//! `delivery_icount` (`ceil(vt(request_icount) + BlockLatency)`), then DELIVERs
//! every response whose `delivery_icount` is at or below the supplied guest
//! icount onto the response ring.
//!
//! ```text
//! service(guest_icount):
//!   ring pair = region.node_directed_ring_pair_mut(vm, vm->BLK, BLK->vm)
//!   process_shmem_inbox(request ring)  -> COMPUTE responses into in-flight queue
//!   advance_to_shmem(guest_icount, response ring) -> DELIVER due responses
//!   report { processed, delivered, next_completion_icount }
//! ```
//!
//! The host never invents a completion time: `delivery_icount` is a pure function
//! of the request icount, the modeled latency, and the fixed icount shift, so the
//! serviced I/O stays icount-deterministic. [`QemuLiveBlockIoServiceStep`]
//! exposes the device's next completion icount, which is the exact device horizon
//! a time-owning plugin must advance to before a blocked guest can complete.

use std::os::fd::BorrowedFd;

use crucible_device::{BaseImage, BlockDevice, BlockLatency, DeviceError, IoCore};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    SLOT_BLK_IO, SetupRegionMapError, mmap_setup_region,
};
use thiserror::Error;

/// In-flight request-queue capacity for the servicer's I/O core.
const SERVICER_INBOX_CAPACITY: u64 = 16;
/// In-flight response-queue capacity for the servicer's I/O core.
const SERVICER_OUTBOX_CAPACITY: u64 = 16;

/// A production host servicer for one live node's `SLOT_BLK_IO` rings.
pub struct QemuLiveBlockIoServicer {
    region: MappedSetupRegion,
    device: BlockDevice,
    vm_slot: u32,
    frames_processed: usize,
    frames_delivered: usize,
}

impl QemuLiveBlockIoServicer {
    /// Maps `shmem_fd` read-write and binds a deterministic block device to `vm_slot`.
    ///
    /// The `icount_shift` must equal the guest's launch-profile icount shift so
    /// the device's `delivery_icount` arithmetic lands in the same virtual-time
    /// domain as the guest. `size_bytes` sizes a deterministic base image whose
    /// byte `i` is `(i % 251) as u8`, so a read of any sector is reproducible
    /// without consulting any host file.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::MapRegion`] when the shared-memory
    /// region cannot be mapped, or [`QemuLiveBlockIoServicerError::Device`] when
    /// the I/O core rejects the shift or ring capacities.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        size_bytes: u64,
    ) -> Result<Self, QemuLiveBlockIoServicerError> {
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveBlockIoServicerError::MapRegion { source })?;
        let core = IoCore::new(
            icount_shift,
            SLOT_BLK_IO as u32,
            SERVICER_INBOX_CAPACITY,
            SERVICER_OUTBOX_CAPACITY,
        )
        .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let base = BaseImage::new(deterministic_base_image(size_bytes));
        let device = BlockDevice::new(core, base, BlockLatency::default());
        Ok(Self {
            region,
            device,
            vm_slot,
            frames_processed: 0,
            frames_delivered: 0,
        })
    }

    /// Drains newly arrived requests and delivers responses due at `guest_icount`.
    ///
    /// COMPUTEs every request frame on the VM-to-device ring into an ordered
    /// in-flight response, then publishes every in-flight response whose
    /// `delivery_icount` is at or below `guest_icount` onto the device-to-VM ring
    /// (waking the guest slot when at least one is published).
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] when the mapped
    /// `SLOT_BLK_IO` rings cannot be borrowed, or
    /// [`QemuLiveBlockIoServicerError::Device`] when request COMPUTE, delivery, or
    /// ring publication fails.
    pub fn service(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicerError> {
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            frames_delivered,
        } = self;
        let vm_slot = *vm_slot;
        let blk_slot = SLOT_BLK_IO as u32;

        let pair = region
            .node_directed_ring_pair_mut(vm_slot, vm_slot, blk_slot, blk_slot, vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        let MappedNodeRingPairMut {
            node_slot,
            first,
            second,
        } = pair;
        let MappedDirectedRingMut {
            header: request_header,
            entries: request_entries,
            ..
        } = first;
        let MappedDirectedRingMut {
            header: response_header,
            entries: response_entries,
            ..
        } = second;

        let inbox = device
            .process_shmem_inbox(request_header, request_entries, node_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        *frames_processed += inbox.processed;

        let delivery = device
            .advance_to_shmem(guest_icount, response_header, response_entries, node_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        *frames_delivered += delivery.delivered;

        Ok(QemuLiveBlockIoServiceStep {
            processed: inbox.processed,
            delivered: delivery.delivered,
            next_completion_icount: device.core().next_exact_local_event(),
        })
    }

    /// Returns the cumulative number of request frames processed so far.
    #[must_use]
    pub const fn frames_processed(&self) -> usize {
        self.frames_processed
    }

    /// Returns the cumulative number of response frames delivered so far.
    #[must_use]
    pub const fn frames_delivered(&self) -> usize {
        self.frames_delivered
    }

    /// Returns the device's next completion icount, when a response is in flight.
    ///
    /// This is the exact device horizon: a blocked guest cannot complete its
    /// request until virtual time reaches this icount, so a time-owning plugin
    /// must advance to it before the response can be delivered.
    #[must_use]
    pub fn next_completion_icount(&self) -> Option<u64> {
        self.device.core().next_exact_local_event()
    }
}

/// The per-call outcome of one [`QemuLiveBlockIoServicer::service`] step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoServiceStep {
    /// Request frames drained and COMPUTEd this call.
    pub processed: usize,
    /// Response frames published to the response ring this call.
    pub delivered: usize,
    /// The device's next completion icount after this call, when one is pending.
    pub next_completion_icount: Option<u64>,
}

/// Builds the deterministic base-image bytes for a device of `size_bytes`.
fn deterministic_base_image(size_bytes: u64) -> Vec<u8> {
    let len = usize::try_from(size_bytes).unwrap_or(usize::MAX);
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// Error returned by the live block-I/O servicer.
#[derive(Debug, Error)]
pub enum QemuLiveBlockIoServicerError {
    /// The shared-memory region could not be mapped read-write.
    #[error("map block-I/O shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The mapped `SLOT_BLK_IO` rings could not be borrowed.
    #[error("access SLOT_BLK_IO rings failed: {source}")]
    RegionAccess {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// The block device rejected a servicing operation.
    #[error("block device servicing failed: {source}")]
    Device {
        /// Underlying device error.
        source: DeviceError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_base_image_is_reproducible_and_sized() {
        let first = deterministic_base_image(512);
        let second = deterministic_base_image(512);
        assert_eq!(first.len(), 512);
        assert_eq!(first, second);
        assert_eq!(first[0], 0);
        assert_eq!(first[251], 0);
        assert_eq!(first[250], 250);
    }
}
