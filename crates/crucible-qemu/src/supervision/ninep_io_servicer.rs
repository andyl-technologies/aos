//! Host servicer for a live node's `SLOT_9P_IO` rings.
//!
//! This is the 9p analogue of [`crate::supervision::QemuLiveBlockIoServicer`]:
//! it maps the node's shared-memory region read-write and composes a
//! deterministic [`NinepDevice`] over a fixed [`FsTree`]. Each `service` call:
//!
//! ```text
//!   process_shmem_inbox(request ring)  -> COMPUTE responses into in-flight queue
//!   advance_to_shmem(guest_icount, response ring) -> DELIVER due responses
//!   store_device_completion_deadline_icount(next_exact_local_event)
//! ```
//!
//! A 9p request's response is due at `delivery_icount = ceil(vt(request_icount) +
//! NinepLatency)`, strictly after the request, so a guest blocked on 9p I/O hits
//! the *same* SCHED-8 device-horizon gap as block I/O: it cannot advance to its
//! own completion. The RFC-0010 0039 patch (a `blk_wait`-style device-wait
//! callback plus a `QEMU_CLOCK_VIRTUAL` delivery-resume timer) closes both the
//! block and the 9p path with one mechanism -- Part A (advance trigger) and Part
//! B (delivery resume) are device-agnostic. Until it lands, a guest's 9p probe
//! stalls at the horizon exactly as block I/O does; the live 9p harness asserts
//! that known stall signature as its pre-0039 baseline.
//!
//! The diagnostics types here parallel the block servicer's; a future
//! device-agnostic `DeviceIoDiagnostics` could DRY the two, but the block
//! harness is already landed and validated, so this mirror keeps them separate.

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible_device::{FsTree, IoCore, NinepDevice, NinepLatency, Node};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    NodeSlotSnapshot, SLOT_9P_IO, SetupRegionMapError, mmap_setup_region,
};
use thiserror::Error;

/// In-flight request-queue capacity for the servicer's I/O core.
const SERVICER_INBOX_CAPACITY: u64 = 16;
/// In-flight response-queue capacity for the servicer's I/O core.
const SERVICER_OUTBOX_CAPACITY: u64 = 16;

/// A production host servicer for one live node's `SLOT_9P_IO` rings.
pub struct QemuLive9pIoServicer {
    region: MappedSetupRegion,
    device: NinepDevice,
    vm_slot: u32,
    frames_processed: usize,
    frames_delivered: usize,
}

impl QemuLive9pIoServicer {
    /// Maps `shmem_fd` read-write and binds a deterministic 9p device to `vm_slot`.
    ///
    /// The `icount_shift` must equal the guest's launch-profile icount shift so
    /// the device's `delivery_icount` arithmetic lands in the same virtual-time
    /// domain as the guest. The backing [`FsTree`] is a fixed, host-independent
    /// tree (a single regular file under the root), so any 9p walk/read is
    /// reproducible without consulting a host filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::MapRegion`] when the shared-memory
    /// region cannot be mapped, [`QemuLive9pIoServicerError::Device`] when the
    /// I/O core rejects the shift or ring capacities, or
    /// [`QemuLive9pIoServicerError::Tree`] when the fixed tree is malformed.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
    ) -> Result<Self, QemuLive9pIoServicerError> {
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLive9pIoServicerError::MapRegion { source })?;
        let core = IoCore::new(
            icount_shift,
            SLOT_9P_IO as u32,
            SERVICER_INBOX_CAPACITY,
            SERVICER_OUTBOX_CAPACITY,
        )
        .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let tree = deterministic_fs_tree()?;
        let device = NinepDevice::new(core, tree, NinepLatency::default());
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
    /// COMPUTEs every 9p request frame on the VM-to-device ring into an ordered
    /// in-flight response, then publishes every in-flight response whose
    /// `delivery_icount` is at or below `guest_icount` onto the device-to-VM ring,
    /// and republishes the next device-completion deadline to the guest node slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::RegionAccess`] when the mapped
    /// `SLOT_9P_IO` rings cannot be borrowed, or
    /// [`QemuLive9pIoServicerError::Device`] when request COMPUTE, delivery, or
    /// ring publication fails.
    pub fn service(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLive9pIoServiceStep, QemuLive9pIoServicerError> {
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            frames_delivered,
        } = self;
        let vm_slot = *vm_slot;
        let ninep_slot = SLOT_9P_IO as u32;

        let pair = region
            .node_directed_ring_pair_mut(vm_slot, vm_slot, ninep_slot, ninep_slot, vm_slot)
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })?;
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
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        *frames_processed += inbox.processed;

        let delivery = device
            .advance_to_shmem(guest_icount, response_header, response_entries, node_slot)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        *frames_delivered += delivery.delivered;

        // Publish the next device-completion deadline to the guest node slot so a
        // time-owning plugin whose guest is blocked on 9p I/O can idle-jump to it
        // (0039 Part A). Zero when nothing is in flight, which retracts any stale
        // deadline.
        let next_completion_icount = device.core().next_exact_local_event();
        node_slot.store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));

        Ok(QemuLive9pIoServiceStep {
            processed: inbox.processed,
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
    /// This is the exact device horizon: a blocked guest cannot complete its 9p
    /// request until virtual time reaches this icount, so a time-owning plugin
    /// must advance to it before the response can be delivered.
    #[must_use]
    pub fn next_completion_icount(&self) -> Option<u64> {
        self.device.core().next_exact_local_event()
    }

    /// Reads the guest VM node slot's published state from the servicer's mapping.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::RegionAccess`] when the guest node
    /// slot cannot be borrowed from the mapped region.
    pub fn vm_node_snapshot(&self) -> Result<NodeSlotSnapshot, QemuLive9pIoServicerError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })?
            .snapshot())
    }
}

/// The per-call outcome of one [`QemuLive9pIoServicer::service`] step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLive9pIoServiceStep {
    /// Request frames drained and COMPUTEd this call.
    pub processed: usize,
    /// Response frames published to the response ring this call.
    pub delivered: usize,
    /// The device's next completion icount after this call, when one is pending.
    pub next_completion_icount: Option<u64>,
}

/// A shared diagnostic sink for one live 9p-I/O servicing run.
///
/// Parallels [`crate::supervision::BlockIoDiagnostics`]: the servicing poll loop
/// writes each observation here and the runner holds a clone (via
/// [`NinepIoDiagnostics::shared`]), reading the accumulated evidence once the
/// advance returns. The atomics exist only so the sink is `Sync` enough to live
/// behind the node's boxed runtime.
#[derive(Debug, Default)]
pub struct NinepIoDiagnostics {
    frames_processed: AtomicUsize,
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

impl NinepIoDiagnostics {
    /// Creates an empty diagnostic sink wrapped for sharing across the boundary.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records one servicing observation from the runtime poll loop.
    ///
    /// `current_icount`, `device_io_active`, and `idle_wake_icount` are the guest
    /// slot's published state at the poll; `serviced` is the servicing outcome.
    // crucible-lint: allow rust-allow -- consumed by the stage-2 live 9p harness (mirrors block_node_gate's diagnostics.record); retained beside the sink it records into, and exercised by this module's unit tests.
    #[allow(dead_code)]
    pub(crate) fn record(
        &self,
        current_icount: u64,
        device_io_active: bool,
        idle_wake_icount: u64,
        serviced: &QemuLive9pIoServiceStep,
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
    pub fn snapshot(&self) -> NinepIoDiagnosticsSnapshot {
        let saw_request = self.first_request_seen.load(Ordering::Relaxed);
        NinepIoDiagnosticsSnapshot {
            frames_processed: self.frames_processed.load(Ordering::Relaxed),
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

/// A plain-value snapshot of the [`NinepIoDiagnostics`] accumulated for a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NinepIoDiagnosticsSnapshot {
    /// Total request frames drained and COMPUTEd across the run.
    pub frames_processed: usize,
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

/// Builds the fixed, host-independent 9p tree the servicer serves.
///
/// A root directory containing a single regular file `hello`; the tree is a pure
/// constant, so every 9p walk/read against it is reproducible without touching a
/// host filesystem.
fn deterministic_fs_tree() -> Result<FsTree, QemuLive9pIoServicerError> {
    let mut children = BTreeMap::new();
    children.insert(
        "hello".to_string(),
        Node::File {
            content: b"hello".to_vec(),
        },
    );
    FsTree::try_new(Node::Directory { children })
        .map_err(|error| QemuLive9pIoServicerError::Tree {
            message: error.to_string(),
        })
}

/// Error returned by the live 9p-I/O servicer.
#[derive(Debug, Error)]
pub enum QemuLive9pIoServicerError {
    /// The shared-memory region could not be mapped read-write.
    #[error("map 9p-I/O shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The mapped `SLOT_9P_IO` rings could not be borrowed.
    #[error("access SLOT_9P_IO rings failed: {source}")]
    RegionAccess {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// The fixed 9p tree could not be constructed.
    #[error("build deterministic 9p tree failed: {message}")]
    Tree {
        /// Human-readable tree construction error.
        message: String,
    },
    /// The 9p device model rejected an operation.
    #[error("9p device operation failed: {source}")]
    Device {
        /// Underlying device error.
        source: crucible_device::DeviceError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed 9p tree is a pure constant: two independent constructions are
    /// byte-for-byte equal. Device-level icount purity (a request's delivery
    /// icount is a function of its request icount, never of host work) is proven
    /// in `crucible-device`'s ninep `run_sequence(skew)` test; the servicer only
    /// plumbs that already-deterministic device onto the shmem rings.
    #[test]
    fn deterministic_fs_tree_is_reproducible() {
        let first = deterministic_fs_tree().expect("fixed 9p tree is well-formed");
        let second = deterministic_fs_tree().expect("fixed 9p tree is well-formed");
        assert_eq!(first, second);
    }

    /// The diagnostics sink is a pure function of the observation sequence:
    /// replaying identical `(icount, service step)` observations into two sinks
    /// yields byte-identical snapshots, and the first-request horizon, max
    /// icount, and cumulative counts accumulate as specified.
    #[test]
    fn diagnostics_accumulate_as_a_pure_function_of_observations() {
        let observations = [
            (10_u64, false, 0_u64, step(0, 0, None)),
            (10, true, 1, step(1, 0, Some(1512))),
            (900, true, 1512, step(0, 0, Some(1512))),
            (1512, true, 1512, step(0, 1, None)),
        ];

        let replay = || {
            let diag = NinepIoDiagnostics::default();
            for (icount, active, idle_wake, serviced) in &observations {
                diag.record(*icount, *active, *idle_wake, serviced);
            }
            diag.snapshot()
        };

        let a = replay();
        let b = replay();
        assert_eq!(a, b, "same observations must yield the same snapshot");

        assert_eq!(a.frames_processed, 1);
        assert_eq!(a.frames_delivered, 1);
        assert_eq!(a.service_calls, 4);
        assert_eq!(a.first_request_icount, Some(10));
        assert_eq!(a.first_completion_horizon, Some(1512));
        assert_eq!(a.max_current_icount, 1512);
        assert_eq!(a.last_current_icount, 1512);
        assert!(a.last_device_io_active);
    }

    fn step(processed: usize, delivered: usize, next: Option<u64>) -> QemuLive9pIoServiceStep {
        QemuLive9pIoServiceStep {
            processed,
            delivered,
            next_completion_icount: next,
        }
    }
}
