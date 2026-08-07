//! Production host-I/O runtime for a live QEMU node.
//!
//! [`QemuLiveHostIoRuntime`] is the first non-test [`QemuHostIoRuntime`]. It maps
//! the plugin's shared-memory region read-only (an independent `MAP_SHARED` view
//! of the same descriptor the node's hot-path channel writes) and, on an
//! `AdvanceCompletion` await, signals QEMU's plugin wake eventfd once and then
//! polls the node slot for the quantum boundary using the shared
//! [`classify_quantum_boundary`] decision -- the same classification the M1
//! quantum-gate scheduler uses, so the runtime and the channel agree bit-for-bit
//! on when a quantum has completed.
//!
//! The single wake signal per advance is load-bearing: the node's shared-memory
//! `start_quantum` futex wake alone releases the boot barrier, but a vCPU parked
//! in its between-quanta idle wait re-parks on the inherited wake eventfd, which
//! only an eventfd signal rouses. The runtime signals it exactly once per advance
//! (never per poll, which would destabilise the plugin's published idle state),
//! mirroring how the M1 scheduler wakes the plugin once per quantum.
//!
//! The runtime observes only the shared-memory advance boundary. Lifecycle
//! awaits (handshake, QMP, process-exit) are not gated here: the node driver
//! observes those directly on its control-socket, QMP, and child handles, so
//! this runtime treats a non-advance await as an immediate host-liveness yield.

use std::fs::File;
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crucible_shmem::{
    DequeuedFaultResult, MappedSetupRegion, MappedSetupRegionAccessError, STATUS_DONE,
    SetupRegionMapError, dequeue_fault_result, mmap_setup_region,
};
use thiserror::Error;

use super::block_io_servicer::{BlockIoDiagnostics, QemuLiveBlockIoServicer};
use crate::quantum::idle_state_from_snapshot;
use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuHostIoRuntime};
use deadline::AdvanceWaitDeadline;

mod deadline;

/// Default host poll interval while awaiting a plugin-published quantum boundary.
///
/// This matches the M1 quantum gate's cadence. The interval only bounds host
/// liveness; the resulting boundary icount is the guest's exact value and never
/// depends on the poll rate.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// A production host-I/O runtime backed by a read-only shared-memory view.
///
/// The runtime's own [`MappedSetupRegion`] is an observer view: it only reads the
/// guest node slot. An optional [`QemuLiveBlockIoServicer`] added with
/// [`QemuLiveHostIoRuntime::with_block_servicer`] is the participant half -- it
/// owns a separate writable mapping confined to the `SLOT_BLK_IO` ring pair and
/// is driven once per advance poll so a guest blocked on real block I/O can make
/// progress.
pub struct QemuLiveHostIoRuntime {
    region: MappedSetupRegion,
    wake: File,
    vm_slot: u32,
    poll_interval: Duration,
    advance_wait_deadline: AdvanceWaitDeadline,
    block: Option<BlockIoServicing>,
}

/// The participant half of the runtime: a block servicer plus its diagnostic sink.
struct BlockIoServicing {
    servicer: QemuLiveBlockIoServicer,
    diagnostics: Arc<BlockIoDiagnostics>,
    coordinator: Option<Box<dyn QemuBlockFaultCoordinator>>,
}

/// Owns exact signal evaluation around one live block servicing pass.
///
/// Production implementations pin the immutable request, evaluate each authored
/// phase, install authenticated directives, advance the device, and persist the
/// resulting evidence. The host-I/O runtime supplies only the guest coordinate;
/// it never invents a fault-free fallback when a coordinator is installed.
pub trait QemuBlockFaultCoordinator: Send {
    /// Services one poll of `servicer` at the observed guest coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when opportunity construction,
    /// signal evaluation, directive installation, device mutation, or evidence
    /// recording fails. Errors fail the enclosing node advance closed.
    fn service_block_io(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<super::QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError>;
}

impl QemuLiveHostIoRuntime {
    /// Maps `shmem_fd` read-only, clones `wake_fd`, and binds the runtime to `vm_slot`.
    ///
    /// The shmem descriptor is the same region the node's hot-path channel writes;
    /// this independent mapping observes the plugin's published node slot without
    /// taking a second owning handle to the channel's mapping. The wake descriptor
    /// is QEMU's plugin wake eventfd: the runtime clones it and signals it once at
    /// the start of each advance await, which is required to rouse a vCPU parked in
    /// its between-quanta idle wait (the node's shared-memory `start_quantum` futex
    /// wake alone does not, exactly as the M1 scheduler signals it per quantum).
    /// A pending advance also re-signals after an unchanged-icount poll so QEMU's
    /// main loop dispatches ordinary asynchronous device completion while the
    /// vCPU is parked.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::MapRegion`] when the shared-memory
    /// region cannot be mapped, or [`QemuLiveHostIoRuntimeError::CloneWakeFd`] when
    /// the wake descriptor cannot be cloned.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        wake_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        Self::from_shmem_fd_with_poll_interval(
            shmem_fd,
            wake_fd,
            region_len,
            vm_slot,
            DEFAULT_POLL_INTERVAL,
        )
    }

    /// Maps the region with an explicit poll interval for the advance await.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::MapRegion`] when the shared-memory
    /// region cannot be mapped, [`QemuLiveHostIoRuntimeError::CloneWakeFd`] when the
    /// wake descriptor cannot be cloned, or
    /// [`QemuLiveHostIoRuntimeError::ZeroPollInterval`] when `poll_interval` is zero.
    pub fn from_shmem_fd_with_poll_interval(
        shmem_fd: BorrowedFd<'_>,
        wake_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        poll_interval: Duration,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        if poll_interval.is_zero() {
            return Err(QemuLiveHostIoRuntimeError::ZeroPollInterval);
        }
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveHostIoRuntimeError::MapRegion { source })?;
        let wake = wake_fd
            .try_clone_to_owned()
            .map(File::from)
            .map_err(|source| QemuLiveHostIoRuntimeError::CloneWakeFd { source })?;
        Ok(Self {
            region,
            wake,
            vm_slot,
            poll_interval,
            advance_wait_deadline: AdvanceWaitDeadline::default(),
            block: None,
        })
    }

    /// Attaches a block-I/O servicer driven once per advance poll.
    ///
    /// The servicer owns its own writable mapping confined to the `SLOT_BLK_IO`
    /// ring pair; `diagnostics` is the shared sink the caller reads back after the
    /// advance. With a servicer attached, each advance poll drains newly arrived
    /// block requests and delivers responses due at the guest's observed icount,
    /// so a guest blocked on real block I/O can make progress.
    #[must_use]
    pub fn with_block_servicer(
        mut self,
        servicer: QemuLiveBlockIoServicer,
        diagnostics: Arc<BlockIoDiagnostics>,
    ) -> Self {
        self.block = Some(BlockIoServicing {
            servicer,
            diagnostics,
            coordinator: None,
        });
        self
    }

    /// Signals QEMU's plugin wake eventfd with the exact eight-byte counter write.
    fn signal_wake(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut wake = &self.wake;
        wake.write_all(&1_u64.to_ne_bytes()).map_err(|error| {
            QemuAsyncDriverRuntimeError::new("signal plugin wake", error.to_string())
        })
    }

    /// Polls the node slot for a quantum boundary within a bounded attempt count.
    ///
    /// Signals the plugin wake eventfd once before polling so a vCPU parked in its
    /// between-quanta idle wait observes the ceiling the node just published.
    fn poll_advance_completion(
        &mut self,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        if !self.advance_wait_deadline.start(timeout) {
            return Err(QemuAsyncDriverRuntimeError::new(
                "start advance completion deadline",
                "timeout deadline overflow",
            ));
        }
        self.signal_wake()?;
        self.repoll_advance_completion(timeout)
    }

    /// Polls for a quantum boundary after the initial plugin wake was sent.
    ///
    /// When two successive pending observations have the same icount, the vCPU
    /// may be parked behind host AIO. Re-signalling the plugin wake cycles QEMU's
    /// main loop without perturbing a guest that is actively retiring
    /// instructions.
    fn repoll_advance_completion(
        &mut self,
        _timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let remaining = self.advance_wait_deadline.remaining().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "repoll advance completion",
                "initial await did not establish a deadline",
            )
        })?;
        if remaining.is_zero() {
            return Ok(QemuAsyncWaitOutcome::TimedOut);
        }
        let attempts = bounded_poll_attempts(remaining, self.poll_interval);
        let mut previous_icount = None;
        for attempt in 0..attempts {
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            // Service block I/O before classifying the boundary: a guest blocked
            // on a probe read cannot reach the ceiling until its response is
            // delivered, so draining and delivering at the observed icount is what
            // lets the advance make progress.
            self.service_block_io(&snapshot)?;
            let idle = idle_state_from_snapshot(snapshot);
            match classify_quantum_boundary(&idle, snapshot.max_advance_icount) {
                QuantumBoundary::Reached { .. } | QuantumBoundary::Paused { .. } => {
                    return Ok(QemuAsyncWaitOutcome::Completed);
                }
                QuantumBoundary::Pending => {
                    if snapshot.status == STATUS_DONE {
                        return Ok(QemuAsyncWaitOutcome::Completed);
                    }
                    if previous_icount == Some(snapshot.current_icount) {
                        self.signal_wake()?;
                    }
                    previous_icount = Some(snapshot.current_icount);
                }
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Ok(QemuAsyncWaitOutcome::TimedOut)
    }

    /// Polls the dedicated lossless result ring while repeatedly waking QEMU.
    fn poll_fault_result(
        &mut self,
        timeout: Duration,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "await fault result",
                "fault-result timeout is zero",
            ));
        }
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        for attempt in 0..attempts {
            self.signal_wake()?;
            let transport = self
                .region
                .fault_result_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "map fault-result transport",
                        source.to_string(),
                    )
                })?;
            let result = dequeue_fault_result(
                transport.ring,
                transport.slots,
                transport.arena_header,
                transport.arena,
                transport.arena_region_offset,
            )
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("dequeue fault result", source.to_string())
            })?;
            if let Some(result) = result {
                return Ok(result);
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault result",
            format!("no result was published within {timeout:?}"),
        ))
    }

    /// Services the block-I/O ring at the guest's observed icount, if attached.
    ///
    /// Drains newly arrived requests and delivers responses due at the guest's
    /// current icount, then records the observation into the shared diagnostics.
    /// Any request or response transition signals the plugin wake fd so QEMU's
    /// parked block coroutine observes the updated rings and device deadline.
    /// This is a no-op when no block servicer is attached.
    fn service_block_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(block) = &mut self.block else {
            return Ok(());
        };
        let serviced = match &mut block.coordinator {
            Some(coordinator) => {
                coordinator.service_block_io(&mut block.servicer, snapshot.current_icount)?
            }
            None => block
                .servicer
                .service(snapshot.current_icount)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("service block io", source.to_string())
                })?,
        };
        block.diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            &serviced,
        );
        if serviced.processed > 0 || serviced.delivered > 0 {
            self.signal_wake()?;
        }
        Ok(())
    }
}

impl QemuHostIoRuntime for QemuLiveHostIoRuntime {
    fn install_block_fault_coordinator(
        &mut self,
        coordinator: Box<dyn QemuBlockFaultCoordinator>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let block = self.block.as_mut().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "install block fault coordinator",
                "live node has no shared-memory block servicer",
            )
        })?;
        block.coordinator = Some(coordinator);
        Ok(())
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        match wait {
            QemuAsyncWait::AdvanceCompletion => self.poll_advance_completion(timeout),
            QemuAsyncWait::Handshake | QemuAsyncWait::QmpCommand | QemuAsyncWait::ProcessEvent => {
                Ok(QemuAsyncWaitOutcome::Completed)
            }
        }
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        match wait {
            QemuAsyncWait::AdvanceCompletion => self.repoll_advance_completion(timeout),
            QemuAsyncWait::Handshake | QemuAsyncWait::QmpCommand | QemuAsyncWait::ProcessEvent => {
                self.await_child(wait, timeout)
            }
        }
    }

    fn await_fault_result(
        &mut self,
        timeout: Duration,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.poll_fault_result(timeout)
    }
}

/// Returns the number of poll attempts that fit within `timeout`, at least one.
fn bounded_poll_attempts(timeout: Duration, poll_interval: Duration) -> u64 {
    let interval = poll_interval.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Maps a node-slot access failure to a runtime await error.
fn map_slot_error(source: MappedSetupRegionAccessError) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new("poll advance completion", source.to_string())
}

/// Error building a [`QemuLiveHostIoRuntime`].
#[derive(Debug, Error)]
pub enum QemuLiveHostIoRuntimeError {
    /// The shared-memory region could not be mapped.
    #[error("map shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The plugin wake eventfd could not be cloned.
    #[error("clone plugin wake eventfd failed: {source}")]
    CloneWakeFd {
        /// Underlying descriptor clone error.
        source: std::io::Error,
    },
    /// The configured poll interval was zero.
    #[error("host-I/O runtime poll interval must be nonzero")]
    ZeroPollInterval,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_poll_attempts_is_at_least_one() {
        assert_eq!(
            bounded_poll_attempts(Duration::ZERO, Duration::from_millis(1)),
            1
        );
        assert_eq!(
            bounded_poll_attempts(Duration::from_micros(1), Duration::from_millis(1)),
            1
        );
    }

    #[test]
    fn bounded_poll_attempts_divides_the_budget() {
        assert_eq!(
            bounded_poll_attempts(Duration::from_millis(10), Duration::from_millis(1)),
            10
        );
        assert_eq!(
            bounded_poll_attempts(Duration::from_millis(1), Duration::from_micros(250)),
            4
        );
    }

    #[test]
    fn bounded_poll_attempts_tolerates_a_zero_interval() {
        assert_eq!(
            bounded_poll_attempts(Duration::from_millis(1), Duration::ZERO),
            1000
        );
    }
}
