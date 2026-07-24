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
//!
//! # Determinism invariant
//!
//! Servicing is a pure function of the observed guest icount. The host poll
//! cadence may change *when* [`QemuLiveBlockIoServicer::service`] runs and *how
//! many* frames it batches per call, but never *which* requests are processed,
//! their COMPUTE result, their order, or their `delivery_icount`: requests are
//! drained in SPSC FIFO order and delivered by the `(delivery_icount, src, seq)`
//! total order, gated on the passed-in guest icount rather than any host clock.
//! Two runs of the same guest therefore observe the identical processed sequence
//! and identical delivery icounts regardless of poll jitter.
//!
//! # Mapping discipline
//!
//! Unlike the observer-only [`crate::QemuLiveHostIoRuntime`], this servicer is a
//! participant: it holds an independent writable mapping. That writable authority
//! is deliberately confined to the `SLOT_BLK_IO` ring pair reached through
//! [`node_directed_ring_pair_mut`](MappedSetupRegion::node_directed_ring_pair_mut)
//! -- the request-ring read cursor, the response-ring frames, and the guest slot's
//! atomic wake word (the SPSC producer/consumer wakes). It never writes the guest
//! node slot's observed fields (current icount, fingerprint, idle state); those
//! stay the read-only province of the runtime, so the block servicer cannot
//! perturb the state the determinism gates observe.

use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible_device::{BaseImage, BlockDevice, BlockLatency, DeviceError, IoCore};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    NodeSlotSnapshot, SLOT_BLK_IO, SetupRegionMapError, mmap_setup_region,
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
        let write_frames_processed = inbox
            .request_kinds
            .iter()
            .filter(|kind| **kind == Some(1))
            .count();
        *frames_processed += inbox.processed;

        let delivery = device
            .advance_to_shmem(guest_icount, response_header, response_entries, node_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        *frames_delivered += delivery.delivered;

        // Publish the next device-completion deadline to the guest node slot so a
        // time-owning plugin whose guest is blocked on device I/O can idle-jump to
        // it. Zero when nothing is in flight (the pending completion was just
        // delivered), which retracts any stale deadline.
        let next_completion_icount = device.core().next_exact_local_event();
        node_slot.store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));

        Ok(QemuLiveBlockIoServiceStep {
            processed: inbox.processed,
            write_frames_processed,
            delivered: delivery.delivered,
            next_completion_icount,
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

    /// Reads the guest VM node slot's published state from the servicer's mapping.
    ///
    /// A caller driving the guest can read `current_icount`, `device_io_active`,
    /// and `idle_wake_icount` here to observe whether the guest is progressing or
    /// blocked on device I/O, without a second mapping of the region.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] when the guest node
    /// slot cannot be borrowed from the mapped region.
    pub fn vm_node_snapshot(&self) -> Result<NodeSlotSnapshot, QemuLiveBlockIoServicerError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?
            .snapshot())
    }
}

/// The per-call outcome of one [`QemuLiveBlockIoServicer::service`] step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoServiceStep {
    /// Request frames drained and COMPUTEd this call.
    pub processed: usize,
    /// Write request frames drained and COMPUTEd this call.
    pub write_frames_processed: usize,
    /// Response frames published to the response ring this call.
    pub delivered: usize,
    /// The device's next completion icount after this call, when one is pending.
    pub next_completion_icount: Option<u64>,
}

/// A shared diagnostic sink for one live block-I/O servicing run.
///
/// The block-servicing poll loop lives inside the [`crate::QemuLiveHostIoRuntime`]
/// that is moved into the node, so a run cannot read the servicer back out
/// afterward. Instead the runtime writes each observation here and the runner
/// holds a clone (via [`BlockIoDiagnostics::shared`]), reading the accumulated
/// evidence once the advance returns. All fields are updated from the single
/// advance-driving thread; the atomics exist only so the sink is `Sync` enough to
/// live behind the node's boxed runtime.
#[derive(Debug, Default)]
pub struct BlockIoDiagnostics {
    frames_processed: AtomicUsize,
    write_frames_processed: AtomicUsize,
    frames_delivered: AtomicUsize,
    service_calls: AtomicUsize,
    first_request_seen: AtomicBool,
    first_request_icount: AtomicU64,
    first_completion_horizon: AtomicU64,
    last_current_icount: AtomicU64,
    max_current_icount: AtomicU64,
    last_device_io_active: AtomicBool,
    last_idle_wake_icount: AtomicU64,
}

impl BlockIoDiagnostics {
    /// Creates an empty diagnostic sink wrapped for sharing across the boundary.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records one servicing observation from the runtime poll loop.
    ///
    /// `current_icount`, `device_io_active`, and `idle_wake_icount` are the guest
    /// slot's published state at the poll; `serviced` is the servicing outcome.
    pub(crate) fn record(
        &self,
        current_icount: u64,
        device_io_active: bool,
        idle_wake_icount: u64,
        serviced: &QemuLiveBlockIoServiceStep,
    ) {
        self.service_calls.fetch_add(1, Ordering::Relaxed);
        if serviced.processed > 0 {
            self.frames_processed
                .fetch_add(serviced.processed, Ordering::Relaxed);
            if !self.first_request_seen.swap(true, Ordering::Relaxed) {
                self.first_request_icount
                    .store(current_icount, Ordering::Relaxed);
                self.first_completion_horizon.store(
                    serviced.next_completion_icount.unwrap_or(0),
                    Ordering::Relaxed,
                );
            }
        }
        if serviced.write_frames_processed > 0 {
            self.write_frames_processed
                .fetch_add(serviced.write_frames_processed, Ordering::Relaxed);
        }
        if serviced.delivered > 0 {
            self.frames_delivered
                .fetch_add(serviced.delivered, Ordering::Relaxed);
        }
        self.last_current_icount
            .store(current_icount, Ordering::Relaxed);
        self.max_current_icount
            .fetch_max(current_icount, Ordering::Relaxed);
        self.last_device_io_active
            .store(device_io_active, Ordering::Relaxed);
        self.last_idle_wake_icount
            .store(idle_wake_icount, Ordering::Relaxed);
    }

    /// Returns a plain-value snapshot of the accumulated observations.
    #[must_use]
    pub fn snapshot(&self) -> BlockIoDiagnosticsSnapshot {
        let saw_request = self.first_request_seen.load(Ordering::Relaxed);
        BlockIoDiagnosticsSnapshot {
            frames_processed: self.frames_processed.load(Ordering::Relaxed),
            write_frames_processed: self.write_frames_processed.load(Ordering::Relaxed),
            frames_delivered: self.frames_delivered.load(Ordering::Relaxed),
            service_calls: self.service_calls.load(Ordering::Relaxed),
            first_request_icount: saw_request
                .then(|| self.first_request_icount.load(Ordering::Relaxed)),
            first_completion_horizon: saw_request.then_some(()).and_then(|()| {
                let horizon = self.first_completion_horizon.load(Ordering::Relaxed);
                (horizon != 0).then_some(horizon)
            }),
            last_current_icount: self.last_current_icount.load(Ordering::Relaxed),
            max_current_icount: self.max_current_icount.load(Ordering::Relaxed),
            last_device_io_active: self.last_device_io_active.load(Ordering::Relaxed),
            last_idle_wake_icount: self.last_idle_wake_icount.load(Ordering::Relaxed),
        }
    }
}

/// A plain-value snapshot of the [`BlockIoDiagnostics`] accumulated for a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockIoDiagnosticsSnapshot {
    /// Total request frames drained and COMPUTEd across the run.
    pub frames_processed: usize,
    /// Total write request frames drained and COMPUTEd across the run.
    pub write_frames_processed: usize,
    /// Total response frames published to the response ring across the run.
    pub frames_delivered: usize,
    /// Number of poll-loop servicing calls made across the run.
    pub service_calls: usize,
    /// Guest icount observed when the first request frame was processed.
    pub first_request_icount: Option<u64>,
    /// Device completion horizon computed for the first processed request.
    pub first_completion_horizon: Option<u64>,
    /// Guest icount observed at the final poll.
    pub last_current_icount: u64,
    /// Highest guest icount observed across the run.
    pub max_current_icount: u64,
    /// Whether the guest slot last advertised active device I/O.
    pub last_device_io_active: bool,
    /// The guest slot's last published idle-wake icount.
    pub last_idle_wake_icount: u64,
}

impl BlockIoDiagnosticsSnapshot {
    /// Compares deterministic block traffic, excluding host poll sample points.
    pub(crate) fn deterministic_observation_eq(&self, other: &Self) -> bool {
        self.frames_processed == other.frames_processed
            && self.write_frames_processed == other.write_frames_processed
            && self.frames_delivered == other.frames_delivered
            && self.first_request_icount == other.first_request_icount
            && self.first_completion_horizon == other.first_completion_horizon
            && self.last_device_io_active == other.last_device_io_active
    }
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

    #[test]
    fn deterministic_diagnostics_ignore_host_poll_cadence() {
        let first = BlockIoDiagnosticsSnapshot {
            frames_processed: 1,
            write_frames_processed: 1,
            frames_delivered: 1,
            service_calls: 17,
            first_request_icount: Some(0),
            first_completion_horizon: Some(1512),
            last_current_icount: 12_000_000,
            max_current_icount: 12_000_000,
            last_device_io_active: false,
            last_idle_wake_icount: 1,
        };
        let second = BlockIoDiagnosticsSnapshot {
            service_calls: 29,
            ..first
        };

        assert_ne!(first, second);
        assert!(first.deterministic_observation_eq(&second));
    }
}
