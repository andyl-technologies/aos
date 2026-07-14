//! Production host-I/O runtime for a live QEMU node.
//!
//! [`QemuLiveHostIoRuntime`] is the first non-test [`QemuHostIoRuntime`]. It maps
//! the plugin's shared-memory region read-only (an independent `MAP_SHARED` view
//! of the same descriptor the node's hot-path channel writes) and, on an
//! `AdvanceCompletion` await, polls the node slot for the quantum boundary using
//! the shared [`classify_quantum_boundary`] decision -- the same classification
//! the M1 quantum-gate scheduler uses, so the runtime and the channel agree
//! bit-for-bit on when a quantum has completed.
//!
//! The runtime observes only the shared-memory advance boundary. Lifecycle
//! awaits (handshake, QMP, process-exit) are not gated here: the node driver
//! observes those directly on its control-socket, QMP, and child handles, so
//! this runtime treats a non-advance await as an immediate host-liveness yield.

use std::os::fd::BorrowedFd;
use std::thread;
use std::time::Duration;

use crucible_shmem::{
    MappedSetupRegion, MappedSetupRegionAccessError, STATUS_DONE, SetupRegionMapError,
    mmap_setup_region,
};
use thiserror::Error;

use crate::quantum::idle_state_from_snapshot;
use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuHostIoRuntime};

/// Default host poll interval while awaiting a plugin-published quantum boundary.
///
/// This matches the M1 quantum gate's cadence. The interval only bounds host
/// liveness; the resulting boundary icount is the guest's exact value and never
/// depends on the poll rate.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// A production host-I/O runtime backed by a read-only shared-memory view.
pub struct QemuLiveHostIoRuntime {
    region: MappedSetupRegion,
    vm_slot: u32,
    poll_interval: Duration,
}

impl QemuLiveHostIoRuntime {
    /// Maps `shmem_fd` read-only and binds the runtime to `vm_slot`.
    ///
    /// The descriptor is the same shared-memory region the node's hot-path
    /// channel writes; this independent mapping observes the plugin's published
    /// node slot without taking a second owning handle to the channel's mapping.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::MapRegion`] when the shared-memory
    /// region cannot be mapped.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        Self::from_shmem_fd_with_poll_interval(shmem_fd, region_len, vm_slot, DEFAULT_POLL_INTERVAL)
    }

    /// Maps the region with an explicit poll interval for the advance await.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::MapRegion`] when the shared-memory
    /// region cannot be mapped, or [`QemuLiveHostIoRuntimeError::ZeroPollInterval`]
    /// when `poll_interval` is zero.
    pub fn from_shmem_fd_with_poll_interval(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        poll_interval: Duration,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        if poll_interval.is_zero() {
            return Err(QemuLiveHostIoRuntimeError::ZeroPollInterval);
        }
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveHostIoRuntimeError::MapRegion { source })?;
        Ok(Self {
            region,
            vm_slot,
            poll_interval,
        })
    }

    /// Polls the node slot for a quantum boundary within a bounded attempt count.
    fn poll_advance_completion(
        &self,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        for attempt in 0..attempts {
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let idle = idle_state_from_snapshot(snapshot);
            match classify_quantum_boundary(&idle, snapshot.max_advance_icount) {
                QuantumBoundary::Reached { .. } | QuantumBoundary::Paused { .. } => {
                    return Ok(QemuAsyncWaitOutcome::Completed);
                }
                QuantumBoundary::Pending => {
                    if snapshot.status == STATUS_DONE {
                        return Ok(QemuAsyncWaitOutcome::Completed);
                    }
                }
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Ok(QemuAsyncWaitOutcome::TimedOut)
    }
}

impl QemuHostIoRuntime for QemuLiveHostIoRuntime {
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
