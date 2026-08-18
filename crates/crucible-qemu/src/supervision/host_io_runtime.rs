//! Production host-I/O runtime for a live QEMU node.
//!
//! [`QemuLiveHostIoRuntime`] is the first non-test [`QemuHostIoRuntime`]. It maps
//! an independent `MAP_SHARED` view of the same descriptor the node's hot-path
//! channel writes and, on an
//! `AdvanceCompletion` await, signals QEMU's plugin wake eventfd once and then
//! polls the node slot for the quantum boundary using the shared
//! [`classify_quantum_boundary`] decision -- the same classification the M1
//! quantum-gate scheduler uses, so the runtime and the channel agree bit-for-bit
//! on when a quantum has completed.
//!
//! The initial wake signal per advance is load-bearing: the node's shared-memory
//! `start_quantum` futex wake alone releases the boot barrier, but a vCPU parked
//! in its between-quanta idle wait re-parks on the inherited wake eventfd, which
//! only an eventfd signal rouses. The runtime also re-signals after an unchanged
//! observation or after servicing device work so QEMU can dispatch asynchronous
//! completion without host polling cadence becoming a guest-time source.
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

use crucible::model::ContentHash;
use crucible_shmem::{
    DequeuedFaultResult, MappedSetupRegion, MappedSetupRegionAccessError, STATUS_DONE, STATUS_IDLE,
    SetupRegionMapError, authorize_advance_ceiling, dequeue_fault_result, mmap_setup_region,
};
use thiserror::Error;

use super::accelerator_io_servicer::QemuLiveAcceleratorServicer;
use super::block_io_servicer::{BlockIoDiagnostics, QemuLiveBlockIoServicer};
use super::ninep_io_servicer::{NinepIoDiagnostics, QemuLive9pIoServicer};
use crate::console_observation::QemuConsoleObservationReader;
use crate::quantum::idle_state_from_snapshot;
use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{
    QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuHostIoCheckpoint,
    QemuHostIoRuntime,
};
use deadline::AdvanceWaitDeadline;

mod deadline;

/// Default host poll interval while awaiting a plugin-published quantum boundary.
///
/// This matches the M1 quantum gate's cadence. The interval only bounds host
/// liveness; the resulting boundary icount is the guest's exact value and never
/// depends on the poll rate.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// A production host-I/O runtime backed by an independently mapped shared-memory view.
///
/// The runtime reads the guest node slot and owns the global coordinated-pause
/// request/clear operations. It does not write scheduler ceilings, ring indices,
/// or plugin-owned slot state. An optional [`QemuLiveBlockIoServicer`] added with
/// [`QemuLiveHostIoRuntime::with_block_servicer`] is the participant half -- it
/// owns a separate writable mapping confined to the `SLOT_BLK_IO` ring pair and
/// is driven once per advance poll so a guest blocked on real block I/O can make
/// progress.
pub struct QemuLiveHostIoRuntime {
    region: MappedSetupRegion,
    wake: Arc<File>,
    vm_slot: u32,
    poll_interval: Duration,
    advance_wait_deadline: AdvanceWaitDeadline,
    /// Plugin publication generation observed immediately before the advance wake.
    advance_wake_publish_generation: Option<u32>,
    block: Option<BlockIoServicing>,
    ninep: Option<NinepIoServicing>,
    accelerator: Option<QemuLiveAcceleratorServicer>,
    console: Option<QemuConsoleObservationReader>,
}

/// The participant half of the runtime: a block servicer plus its diagnostic sink.
struct BlockIoServicing {
    servicer: QemuLiveBlockIoServicer,
    diagnostics: Arc<BlockIoDiagnostics>,
    coordinator: Option<Box<dyn QemuBlockFaultCoordinator>>,
}

/// The participant half of the runtime for one shared-memory 9p device.
struct NinepIoServicing {
    servicer: QemuLive9pIoServicer,
    diagnostics: Arc<NinepIoDiagnostics>,
    coordinator: Option<Box<dyn QemuNinepFaultCoordinator>>,
}

/// Owns exact signal evaluation around one live block servicing pass.
///
/// Production implementations pin the immutable request, evaluate each authored
/// phase, install authenticated directives, advance the device, and persist the
/// resulting evidence. The host-I/O runtime supplies only the guest coordinate;
/// it never invents a fault-free fallback when a coordinator is installed.
pub trait QemuBlockFaultCoordinator: Send {
    /// Applies storage-targeted actions at one exact scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when a matching boundary action
    /// cannot be resolved, mutated, or recorded atomically.
    fn apply_boundary_actions(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        coordinate: crucible::model::FaultCoordinate,
        evaluation_sequence: u64,
        actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError>;

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

/// Owns exact signal evaluation around one live 9p servicing pass.
pub trait QemuNinepFaultCoordinator: Send {
    /// Services one request/delivery pass at the observed guest coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when opportunity construction,
    /// signal evaluation, state mutation, or evidence recording fails.
    fn service_ninep_io(
        &mut self,
        servicer: &mut QemuLive9pIoServicer,
        guest_icount: u64,
    ) -> Result<super::QemuLive9pIoServiceStep, QemuAsyncDriverRuntimeError>;
}

impl QemuLiveHostIoRuntime {
    /// Maps `shmem_fd`, clones `wake_fd`, and binds the runtime to `vm_slot`.
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
            wake: Arc::new(wake),
            vm_slot,
            poll_interval,
            advance_wait_deadline: AdvanceWaitDeadline::default(),
            advance_wake_publish_generation: None,
            block: None,
            ninep: None,
            accelerator: None,
            console: None,
        })
    }

    /// Attaches a block-I/O servicer driven once per advance poll.
    ///
    /// The servicer owns its own writable mapping confined to the `SLOT_BLK_IO`
    /// ring pair; `diagnostics` is the shared sink the caller reads back after the
    /// advance. With a servicer attached, each advance poll drains newly arrived
    /// block requests and delivers responses due at the guest's observed icount,
    /// so a guest blocked on real block I/O can make progress.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuLiveBlockIoServicerError`] when the device's
    /// remote-mutation notification channel is poisoned or was already attached
    /// to a runtime.
    pub fn with_block_servicer(
        mut self,
        servicer: QemuLiveBlockIoServicer,
        diagnostics: Arc<BlockIoDiagnostics>,
    ) -> Result<Self, super::QemuLiveBlockIoServicerError> {
        servicer
            .shared_device()
            .attach_notification_wake(Arc::clone(&self.wake))?;
        self.block = Some(BlockIoServicing {
            servicer,
            diagnostics,
            coordinator: None,
        });
        Ok(self)
    }

    /// Attaches a 9p servicer driven once per advance poll.
    ///
    /// The servicer owns the `SLOT_9P_IO` rings and serves the immutable World
    /// tree supplied at launch. Each poll drains requests, advances virtual
    /// device time, and publishes due replies before the boundary is classified.
    #[must_use]
    pub fn with_ninep_servicer(
        mut self,
        servicer: QemuLive9pIoServicer,
        diagnostics: Arc<NinepIoDiagnostics>,
    ) -> Self {
        self.ninep = Some(NinepIoServicing {
            servicer,
            diagnostics,
            coordinator: None,
        });
        self
    }

    /// Attaches the production deterministic accelerator adapter.
    #[must_use]
    pub fn with_accelerator_servicer(mut self, servicer: QemuLiveAcceleratorServicer) -> Self {
        self.accelerator = Some(servicer);
        self
    }

    /// Attaches an output-only QEMU console reader and its boundary spool.
    ///
    /// The stream is drained during every in-flight advance poll so guest
    /// console backpressure cannot prevent QEMU from reaching its scheduler
    /// ceiling. Bytes remain in `spool` until the node emits them at that exact
    /// completed boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::DuplicateConsole`] when a console
    /// is already attached.
    pub(crate) fn with_console_observation(
        mut self,
        reader: QemuConsoleObservationReader,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        if self.console.is_some() {
            return Err(QemuLiveHostIoRuntimeError::DuplicateConsole);
        }
        self.console = Some(reader);
        Ok(self)
    }

    /// Signals QEMU's plugin wake eventfd with the exact eight-byte counter write.
    fn write_wake_doorbell(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut wake = self.wake.as_ref();
        wake.write_all(&1_u64.to_ne_bytes()).map_err(|error| {
            QemuAsyncDriverRuntimeError::new("signal plugin wake", error.to_string())
        })
    }

    /// Publishes a control request and rings QEMU's main-loop eventfd.
    fn signal_wake(&self) -> Result<u32, QemuAsyncDriverRuntimeError> {
        let request = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .request_control_boundary()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "request plugin control boundary",
                    source.to_string(),
                )
            })?;
        self.write_wake_doorbell()?;
        Ok(request)
    }

    /// Aborts a coordinated pause and wakes both plugin wait mechanisms.
    fn abort_checkpoint_pause_with_wake(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.region.header().clear_pause();
        let futex_result = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)
            .and_then(|slot| {
                slot.wake_for_frame_delivery().map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "resume from checkpoint pause",
                        source.to_string(),
                    )
                })
            });
        let doorbell_result = self.signal_wake();
        match (futex_result, doorbell_result) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(futex), Ok(_)) => Err(futex),
            (Ok(_), Err(doorbell)) => Err(doorbell),
            (Err(futex), Err(doorbell)) => Err(QemuAsyncDriverRuntimeError::new(
                "resume from checkpoint pause",
                format!("futex wake failed: {futex}; doorbell wake failed: {doorbell}"),
            )),
        }
    }

    /// Releases a failed pause transaction while retaining both diagnostics.
    fn fail_checkpoint_pause(
        &mut self,
        primary: QemuAsyncDriverRuntimeError,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match self.abort_checkpoint_pause_with_wake() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(QemuAsyncDriverRuntimeError::new(
                "rollback failed checkpoint pause",
                format!("primary failure: {primary}; pause release failure: {cleanup}"),
            )),
        }
    }

    /// Polls the node slot for a quantum boundary within a bounded attempt count.
    ///
    /// Signals the plugin wake eventfd once before polling so a vCPU parked in its
    /// between-quanta idle wait observes the ceiling the node just published.
    ///
    /// A normal advance deliberately does not request a control boundary. An idle
    /// callback treats such a request as an instruction to return to QEMU's main
    /// loop without authorizing the queued idle-time jump. If QEMU then remains
    /// parked, the very request intended to prove wake consumption can strand the
    /// advance. Instead, the runtime records the plugin-owned publication
    /// generation and requires a later publication before accepting a boundary.
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
        let snapshot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot();
        self.advance_wake_publish_generation = Some(snapshot.publish_gen);
        self.write_wake_doorbell()?;
        self.repoll_advance_completion(timeout)
    }

    /// Polls for a quantum boundary after the initial plugin wake was sent.
    ///
    /// A change from the publication generation captured by
    /// [`Self::poll_advance_completion`] proves that the plugin observed the
    /// wake. Later device completions ring only the eventfd and do not replace
    /// this one-shot fence. The completed-quantum clamp performs a separate
    /// post-device control-token handshake before this runtime returns.
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
        for attempt in 0..attempts {
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            if self
                .advance_wake_publish_generation
                .is_some_and(|generation| snapshot.publish_gen != generation)
            {
                self.advance_wake_publish_generation = None;
            }
            // Service block I/O before classifying the boundary: a guest blocked
            // on a probe read cannot reach the ceiling until its response is
            // delivered, so draining and delivering at the observed icount is what
            // lets the advance make progress.
            self.service_block_io(&snapshot)?;
            self.service_ninep_io(&snapshot)?;
            self.service_accelerator_io(&snapshot)?;
            self.publish_device_completion_deadline()?;
            let idle = idle_state_from_snapshot(snapshot);
            let wake_unacknowledged = advance_wake_publication_is_unobserved(
                self.advance_wake_publish_generation,
                &snapshot,
            );
            match classify_after_host_wake(&idle, snapshot.max_advance_icount, wake_unacknowledged)
            {
                QuantumBoundary::Reached { .. } | QuantumBoundary::Paused { .. } => {
                    self.clamp_completed_quantum(&snapshot)?;
                    self.service_console_output()?;
                    return Ok(QemuAsyncWaitOutcome::Completed);
                }
                QuantumBoundary::Pending => {
                    if snapshot.status == STATUS_DONE {
                        self.advance_wake_publish_generation = None;
                        return Ok(QemuAsyncWaitOutcome::Completed);
                    }
                    if self.advance_wake_publish_generation.is_none() && attempt % 16 == 15 {
                        self.write_wake_doorbell()?;
                    }
                }
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Ok(QemuAsyncWaitOutcome::TimedOut)
    }

    /// Revokes the unused tail of a completed quantum before returning it.
    ///
    /// A reached boundary already equals its ceiling. An early idle boundary
    /// can retain a future ceiling, however, and QEMU may otherwise consume it
    /// after the host records completion. Clamping makes every authorization
    /// single-use; the next quantum must explicitly publish its own ceiling.
    fn clamp_completed_quantum(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let ceiling =
            authorize_advance_ceiling(snapshot.current_icount, snapshot.current_icount, None)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("clamp completed quantum", source.to_string())
                })?;
        self.region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .publish_scheduler_ceiling(ceiling)
            .map(|_| ())
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "publish completed-quantum ceiling",
                    source.to_string(),
                )
            })?;

        // The futex publication revokes TCG dispatch, but QEMU's main loop can
        // still own a device bottom half queued by the completed slice. Probe
        // the drained eventfd boundary after the clamp and wait for its paired
        // post-device publication. This makes the later read-only checkpoint
        // readiness observation stable: any newly submitted coroutine is
        // already represented by `device_io_active` before the quantum returns.
        let request = self.signal_wake()?;
        let remaining = self.advance_wait_deadline.remaining().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "acknowledge completed-quantum clamp",
                "advance deadline expired before the clamp probe",
            )
        })?;
        let attempts = bounded_poll_attempts(remaining, self.poll_interval);
        let mut last_observed_state = None;
        let mut boundary_acknowledged = false;
        let expected_idle_wake_icount = if snapshot.status == STATUS_IDLE {
            snapshot.idle_wake_icount
        } else {
            snapshot.current_icount
        };
        for attempt in 0..attempts {
            self.service_console_output()?;
            let observed = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let block_progress = self.service_block_io(&observed)?;
            let ninep_progress = self.service_ninep_io(&observed)?;
            let accelerator_progress = self.service_accelerator_io(&observed)?;
            let device_progress = block_progress || ninep_progress || accelerator_progress;
            last_observed_state = Some((
                observed.control_boundary_ack,
                observed.current_icount,
                observed.idle_wake_icount,
                observed.status,
                observed.device_io_active,
                device_progress,
            ));
            if device_progress {
                self.publish_device_completion_deadline()?;
            }
            if control_boundary_request_is_acknowledged(request, &observed) {
                boundary_acknowledged = true;
            }
            // The control callback publishes the exact clamped coordinate
            // before release-acknowledging the request. A node that was already
            // idle must retain its future deadline so `finish_quantum` can prove
            // the early pause against the original horizon; a previously
            // running node is fenced idle at the current coordinate. In both
            // cases, newly serviced device work requires another observation.
            if completed_quantum_clamp_is_settled(
                boundary_acknowledged,
                snapshot.current_icount,
                expected_idle_wake_icount,
                device_progress,
                &observed,
            ) {
                return Ok(());
            }
            if attempt + 1 < attempts {
                // A wake can be drained while QEMU is still releasing an idle
                // time-advance barrier. Its completion path schedules the same
                // post-device callback, but re-signal at a bounded cadence so
                // an overlapping main-loop edge cannot strand the probe.
                if attempt % 16 == 15 {
                    self.write_wake_doorbell()?;
                }
                thread::sleep(self.poll_interval);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "acknowledge completed-quantum clamp",
            format!(
                "QEMU did not publish the post-device control boundary within {remaining:?}: requested token {request}, expected current icount {}, expected idle wake icount {expected_idle_wake_icount}, last observation {}",
                snapshot.current_icount,
                last_observed_state.map_or_else(
                    || String::from("none"),
                    |(ack, current, idle_wake, status, device_active, device_progress)| format!(
                        "token {ack}, current icount {current}, idle wake icount {idle_wake}, status {status}, device I/O active {device_active}, device progress {device_progress}"
                    ),
                )
            ),
        ))
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

    /// Drains all currently available console bytes into boundary staging.
    fn service_console_output(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(console) = &mut self.console else {
            return Ok(());
        };
        console.drain_available()
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
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(block) = &mut self.block else {
            return Ok(false);
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
        let made_progress = serviced.processed > 0 || serviced.delivered > 0;
        if made_progress {
            self.write_wake_doorbell()?;
        }
        Ok(made_progress)
    }

    /// Services the 9p ring at the guest's observed coordinate, if attached.
    fn service_ninep_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(ninep) = &mut self.ninep else {
            return Ok(false);
        };
        let serviced = match &mut ninep.coordinator {
            Some(coordinator) => {
                coordinator.service_ninep_io(&mut ninep.servicer, snapshot.current_icount)?
            }
            None => ninep
                .servicer
                .service(snapshot.current_icount)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("service 9p io", source.to_string())
                })?,
        };
        ninep.diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            &serviced,
        );
        let made_progress = serviced.processed > 0 || serviced.delivered > 0;
        if made_progress {
            self.write_wake_doorbell()?;
        }
        Ok(made_progress)
    }

    fn service_accelerator_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(accelerator) = &mut self.accelerator else {
            return Ok(false);
        };
        let serviced = accelerator
            .service(snapshot.current_icount)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("service accelerator io", source.to_string())
            })?;
        let made_progress = serviced.processed > 0 || serviced.delivered > 0;
        if made_progress {
            self.write_wake_doorbell()?;
        }
        Ok(made_progress)
    }

    /// Publishes the earliest exact completion across every attached host device.
    fn publish_device_completion_deadline(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let block = self
            .block
            .as_ref()
            .map(|block| block.servicer.next_completion_icount())
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "inspect block completion deadline",
                    source.to_string(),
                )
            })?
            .flatten();
        let ninep = self
            .ninep
            .as_ref()
            .and_then(|ninep| ninep.servicer.next_completion_icount());
        let accelerator = self
            .accelerator
            .as_ref()
            .and_then(QemuLiveAcceleratorServicer::next_completion_icount);
        let deadline = [block, ninep, accelerator].into_iter().flatten().min();
        self.region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .store_device_completion_deadline_icount(deadline.unwrap_or(0));
        Ok(())
    }
}

impl QemuHostIoRuntime for QemuLiveHostIoRuntime {
    fn checkpoint_device_io_is_quiescent(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot()
            .device_io_active
            == 0)
    }

    /// Requests an exact plugin boundary and hands QEMU's execution path to QMP.
    fn quiesce_for_checkpoint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "quiesce for checkpoint",
                "checkpoint pause timeout is zero",
            ));
        }
        let slot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?;
        let initial_snapshot = slot.snapshot();
        let initial_publish_gen = initial_snapshot.publish_gen;
        if let Err(source) = self.region.header().request_pause([slot]) {
            return self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
                "request checkpoint pause",
                source.to_string(),
            ));
        }
        // Revoke the unused tail of the preceding quantum before any wake can
        // make an idle vCPU runnable. The pause flag is already visible, and a
        // later normal quantum must publish a fresh ceiling; retaining the old
        // future ceiling here would permit one in-flight TCG slice before the
        // main loop consumes the checkpoint control fd.
        let checkpoint_ceiling = authorize_advance_ceiling(
            initial_snapshot.current_icount,
            initial_snapshot.current_icount,
            None,
        )
        .map_err(|source| {
            QemuAsyncDriverRuntimeError::new("clamp checkpoint ceiling", source.to_string())
        });
        let checkpoint_ceiling = match checkpoint_ceiling {
            Ok(ceiling) => ceiling,
            Err(source) => return self.fail_checkpoint_pause(source),
        };
        if let Err(source) = slot.publish_scheduler_ceiling(checkpoint_ceiling) {
            return self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
                "publish checkpoint ceiling",
                source.to_string(),
            ));
        }
        let mut wake_control_boundary_ack = match self.signal_wake() {
            Ok(request) => Some(request),
            Err(source) => return self.fail_checkpoint_pause(source),
        };
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let mut last_observed = None;
        for attempt in 0..attempts {
            let snapshot = match self.region.node_slot(self.vm_slot).map_err(map_slot_error) {
                Ok(slot) => slot.snapshot(),
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            if wake_control_boundary_ack
                .is_some_and(|request| control_boundary_request_is_acknowledged(request, &snapshot))
            {
                wake_control_boundary_ack = None;
            }
            last_observed = Some((
                snapshot.publish_gen,
                snapshot.status,
                snapshot.current_icount,
                snapshot.idle_wake_icount,
                snapshot.device_io_active,
            ));
            // A request can enter QEMU's device coroutine in the main-loop
            // slice between the plugin's exact pause publication and native
            // stop consuming its queued request. The RR fence prevents any
            // further guest dispatch, while servicing here lets QEMU's normal
            // block/ninep/accelerator drain reach the same quiescent boundary.
            let block_progress = match self.service_block_io(&snapshot) {
                Ok(progress) => progress,
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            let ninep_progress = match self.service_ninep_io(&snapshot) {
                Ok(progress) => progress,
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            let accelerator_progress = match self.service_accelerator_io(&snapshot) {
                Ok(progress) => progress,
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            let device_progress = block_progress || ninep_progress || accelerator_progress;
            if device_progress && wake_control_boundary_ack.is_none() {
                // Each servicing path signals QEMU after publishing its
                // response. The snapshot predates consumption of that wake,
                // so it cannot prove that the guest is quiesced even when it
                // contains an earlier pause acknowledgement.
                wake_control_boundary_ack = match self.signal_wake() {
                    Ok(request) => Some(request),
                    Err(source) => return self.fail_checkpoint_pause(source),
                };
            }
            if let Err(source) = self.publish_device_completion_deadline() {
                return self.fail_checkpoint_pause(source);
            }
            if wake_control_boundary_ack.is_none()
                && snapshot.status == crucible_shmem::STATUS_IDLE
                && snapshot.idle_wake_icount == snapshot.current_icount
                && snapshot.device_io_active == 0
            {
                return Ok(());
            }
            if attempt + 1 < attempts {
                if wake_control_boundary_ack.is_none() {
                    wake_control_boundary_ack = match self.signal_wake() {
                        Ok(request) => Some(request),
                        Err(source) => return self.fail_checkpoint_pause(source),
                    };
                }
                thread::sleep(self.poll_interval);
            }
        }
        let detail = last_observed.map_or_else(
            || String::from("no node-slot snapshot was observed"),
            |(publish_gen, status, current_icount, idle_wake_icount, device_io_active)| {
                format!(
                    "initial publish generation {initial_publish_gen}, last publish generation {publish_gen}, status {status}, current icount {current_icount}, idle wake icount {idle_wake_icount}, device I/O active {device_io_active}"
                )
            },
        );
        self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
            "await checkpoint pause",
            format!("plugin did not acknowledge an exact boundary within {timeout:?}: {detail}"),
        ))
    }

    fn clear_checkpoint_pause_while_stopped(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        // QMP has already confirmed RUN_STATE_PAUSED. Clearing the protocol
        // flag is sufficient for the later `cont`; waking either the shared
        // futex or QEMU's doorbell here can re-enter the vCPU-idle callback
        // while the VM remains stopped. That callback waits with the BQL held,
        // which would prevent the intervening VMState QMP job from running.
        self.region.header().clear_pause();
        Ok(())
    }

    fn abort_checkpoint_pause(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.abort_checkpoint_pause_with_wake()
    }

    fn has_pending_device_io(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let block = self
            .block
            .as_mut()
            .map(|block| block.servicer.has_pending_work())
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("inspect pending block I/O", source.to_string())
            })?;
        let ninep = self
            .ninep
            .as_mut()
            .map(|ninep| ninep.servicer.has_pending_work())
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("inspect pending 9p I/O", source.to_string())
            })?;
        let accelerator = self
            .accelerator
            .as_mut()
            .map(QemuLiveAcceleratorServicer::has_pending_work)
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "inspect pending accelerator I/O",
                    source.to_string(),
                )
            })?;
        Ok(block || ninep || accelerator)
    }

    fn checkpoint_host_io(
        &mut self,
        execution_binding: ContentHash,
    ) -> Result<QemuHostIoCheckpoint, QemuAsyncDriverRuntimeError> {
        let block = self
            .block
            .as_mut()
            .map(|block| block.servicer.checkpoint(execution_binding))
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("checkpoint host block I/O", source.to_string())
            })?;
        let ninep = self
            .ninep
            .as_mut()
            .map(|ninep| ninep.servicer.checkpoint(execution_binding))
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("checkpoint host 9p I/O", source.to_string())
            })?;
        let accelerator = self
            .accelerator
            .as_ref()
            .map(QemuLiveAcceleratorServicer::checkpoint);
        Ok(QemuHostIoCheckpoint::with_devices(
            execution_binding,
            block,
            ninep,
            accelerator,
        ))
    }

    fn validate_host_io_checkpoint(
        &mut self,
        execution_binding: ContentHash,
        checkpoint: &QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if checkpoint.execution_binding != execution_binding {
            return Err(QemuAsyncDriverRuntimeError::new(
                "validate host-I/O checkpoint",
                "host-I/O checkpoint is paired with another QEMU VMState identity",
            ));
        }
        match (self.block.as_mut(), checkpoint.block.as_ref()) {
            (Some(block), Some(checkpoint)) => block
                .servicer
                .validate_checkpoint(execution_binding, checkpoint)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "validate host block-I/O checkpoint",
                        source.to_string(),
                    )
                }),
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "validate host-I/O checkpoint",
                "captured block topology does not match the live host-I/O runtime",
            )),
        }?;
        match (self.ninep.as_mut(), checkpoint.ninep.as_ref()) {
            (Some(ninep), Some(checkpoint)) => ninep
                .servicer
                .validate_checkpoint(execution_binding, checkpoint)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "validate host 9p-I/O checkpoint",
                        source.to_string(),
                    )
                }),
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "validate host-I/O checkpoint",
                "captured 9p topology does not match the live host-I/O runtime",
            )),
        }?;
        match (self.accelerator.as_ref(), checkpoint.accelerator.as_ref()) {
            (Some(accelerator), Some(checkpoint)) => accelerator
                .validate_checkpoint(checkpoint)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "validate host accelerator checkpoint",
                        source.to_string(),
                    )
                }),
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "validate host-I/O checkpoint",
                "captured accelerator topology does not match the live host-I/O runtime",
            )),
        }
    }

    fn restore_host_io_checkpoint(
        &mut self,
        execution_binding: ContentHash,
        checkpoint: &QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.validate_host_io_checkpoint(execution_binding, checkpoint)?;
        let prior_block = self
            .block
            .as_mut()
            .map(|block| block.servicer.checkpoint(execution_binding))
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "capture block rollback checkpoint",
                    source.to_string(),
                )
            })?;
        let prior_ninep = self
            .ninep
            .as_mut()
            .map(|ninep| ninep.servicer.checkpoint(execution_binding))
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "capture 9p rollback checkpoint",
                    source.to_string(),
                )
            })?;
        let prior_accelerator = self
            .accelerator
            .as_ref()
            .map(QemuLiveAcceleratorServicer::checkpoint);
        match (self.block.as_mut(), checkpoint.block.as_ref()) {
            (Some(block), Some(checkpoint)) => block
                .servicer
                .restore_checkpoint(execution_binding, checkpoint)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "restore host block-I/O checkpoint",
                        source.to_string(),
                    )
                }),
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "restore host-I/O checkpoint",
                "validated block topology changed before commit",
            )),
        }?;
        let ninep_result = match (self.ninep.as_mut(), checkpoint.ninep.as_ref()) {
            (Some(ninep), Some(checkpoint)) => ninep
                .servicer
                .restore_checkpoint(execution_binding, checkpoint)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "restore host 9p-I/O checkpoint",
                        source.to_string(),
                    )
                }),
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "restore host-I/O checkpoint",
                "validated 9p topology changed before commit",
            )),
        };
        if let Err(error) = ninep_result {
            if let (Some(block), Some(prior)) = (self.block.as_mut(), prior_block.as_ref()) {
                block
                    .servicer
                    .restore_checkpoint(execution_binding, prior)
                    .map_err(|rollback| {
                        QemuAsyncDriverRuntimeError::new(
                            "roll back host block-I/O checkpoint",
                            format!(
                                "9p restore failed: {error}; block rollback failed: {rollback}"
                            ),
                        )
                    })?;
            }
            return Err(error);
        }
        let accelerator_result = match (self.accelerator.as_mut(), checkpoint.accelerator.as_ref())
        {
            (Some(accelerator), Some(checkpoint)) => accelerator
                .restore_checkpoint(checkpoint)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "restore host accelerator checkpoint",
                        source.to_string(),
                    )
                }),
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "restore host-I/O checkpoint",
                "validated accelerator topology changed before commit",
            )),
        };
        if let Err(error) = accelerator_result {
            let mut rollback_failures = Vec::new();
            if let (Some(ninep), Some(prior)) = (self.ninep.as_mut(), prior_ninep.as_ref())
                && let Err(rollback) = ninep.servicer.restore_checkpoint(execution_binding, prior)
            {
                rollback_failures.push(format!("9p: {rollback}"));
            }
            if let (Some(block), Some(prior)) = (self.block.as_mut(), prior_block.as_ref())
                && let Err(rollback) = block.servicer.restore_checkpoint(execution_binding, prior)
            {
                rollback_failures.push(format!("block: {rollback}"));
            }
            if let (Some(accelerator), Some(prior)) =
                (self.accelerator.as_mut(), prior_accelerator.as_ref())
                && let Err(rollback) = accelerator.restore_checkpoint(prior)
            {
                rollback_failures.push(format!("accelerator: {rollback}"));
            }
            if rollback_failures.is_empty() {
                return Err(error);
            }
            return Err(QemuAsyncDriverRuntimeError::new(
                "roll back aggregate host-I/O checkpoint",
                format!(
                    "accelerator restore failed: {error}; rollback failed: {}",
                    rollback_failures.join(", ")
                ),
            ));
        }
        self.publish_device_completion_deadline()?;
        Ok(())
    }

    fn checkpoint_block_boundary_state(
        &self,
    ) -> Result<Option<crucible_device::block::BlockFaultState>, QemuAsyncDriverRuntimeError> {
        self.block
            .as_ref()
            .map(|block| {
                block.servicer.storage_fault_state().map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "capture block boundary state",
                        source.to_string(),
                    )
                })
            })
            .transpose()
    }

    fn shared_block_device(&self) -> Option<crate::QemuSharedBlockDevice> {
        self.block
            .as_ref()
            .map(|block| block.servicer.shared_device())
    }

    fn restore_block_boundary_state(
        &mut self,
        state: Option<crucible_device::block::BlockFaultState>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match (self.block.as_mut(), state) {
            (Some(block), Some(state)) => {
                block
                    .servicer
                    .restore_storage_fault_state(state)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "restore block boundary state",
                            source.to_string(),
                        )
                    })?;
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(QemuAsyncDriverRuntimeError::new(
                "restore block boundary state",
                "captured block state does not match the live host-I/O topology",
            )),
        }
    }

    fn apply_block_boundary_actions(
        &mut self,
        coordinate: crucible::model::FaultCoordinate,
        evaluation_sequence: u64,
        actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(block) = self.block.as_mut() else {
            return Ok(());
        };
        let Some(coordinator) = block.coordinator.as_mut() else {
            return Err(QemuAsyncDriverRuntimeError::new(
                "apply block boundary actions",
                "live block servicer has no signal coordinator",
            ));
        };
        coordinator.apply_boundary_actions(
            &mut block.servicer,
            coordinate,
            evaluation_sequence,
            actions,
        )
    }

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

    fn install_ninep_fault_coordinator(
        &mut self,
        coordinator: Box<dyn QemuNinepFaultCoordinator>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let ninep = self.ninep.as_mut().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "install 9p fault coordinator",
                "live node has no shared-memory 9p servicer",
            )
        })?;
        if ninep.coordinator.is_some() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "install 9p fault coordinator",
                "live 9p servicer already owns a signal coordinator",
            ));
        }
        ninep.servicer.require_fault_directives();
        ninep.coordinator = Some(coordinator);
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

/// Classifies a snapshot only after QEMU acknowledges the latest host wake.
///
/// The initial quantum wake and a servicing pass that publishes a response can
/// both make an idle guest runnable. A snapshot from before QEMU consumes that
/// wake no longer proves that the guest remains parked, even if it describes an
/// otherwise complete boundary. Treating it as pending forces the poll loop to
/// observe a later stable plugin publication first.
fn classify_after_host_wake(
    idle: &crate::QemuNodeIdleState,
    ceiling: u64,
    wake_unacknowledged: bool,
) -> QuantumBoundary {
    if wake_unacknowledged {
        QuantumBoundary::Pending
    } else {
        classify_quantum_boundary(idle, ceiling)
    }
}

/// Returns whether the plugin has not yet published after the host wake.
fn advance_wake_publication_is_unobserved(
    initial_generation: Option<u32>,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    initial_generation.is_some_and(|generation| snapshot.publish_gen == generation)
}

/// Returns whether the plugin release-acknowledged an even host request.
///
/// Other runtime operations may complete their own handshakes while an advance
/// is polling. Consequently, the observed odd token may be a later
/// acknowledgement rather than the request's immediate successor. Tokens use
/// wrapping serial-number order: an odd value less than half the `u32` space
/// ahead of `request` acknowledges it, while the odd predecessor is stale.
fn control_boundary_request_is_acknowledged(
    request: u32,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    let observed = snapshot.control_boundary_ack;
    let forward_distance = observed.wrapping_sub(request);
    request & 1 == 0
        && observed & 1 == 1
        && forward_distance != 0
        && forward_distance < (1_u32 << 31)
}

/// Returns whether a post-device clamp publication is safe to expose.
fn completed_quantum_clamp_is_settled(
    boundary_acknowledged: bool,
    expected_current_icount: u64,
    expected_idle_wake_icount: u64,
    device_progress: bool,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    boundary_acknowledged
        && !device_progress
        && snapshot.current_icount == expected_current_icount
        && snapshot.status == STATUS_IDLE
        && snapshot.idle_wake_icount == expected_idle_wake_icount
        && snapshot.device_io_active == 0
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
    /// More than one console stream was attached to one node runtime.
    #[error("QEMU host-I/O runtime already has a console stream")]
    DuplicateConsole,
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

    #[test]
    fn unacknowledged_host_wake_invalidates_an_idle_snapshot() {
        let idle = crate::QemuNodeIdleState {
            current_icount: crucible::Icount { retired: 40 },
            next_deadline: Some(crucible::Icount { retired: 200 }),
        };

        assert_eq!(
            classify_after_host_wake(&idle, 100, false),
            QuantumBoundary::Paused {
                at: 40,
                deadline: 200,
            }
        );
        assert_eq!(
            classify_after_host_wake(&idle, 100, true),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn advance_requires_a_plugin_publication_after_its_wake() {
        let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
        let initial = slot.snapshot();
        assert!(advance_wake_publication_is_unobserved(
            Some(initial.publish_gen),
            &initial,
        ));

        slot.publish_control_boundary(0, 0, 0)
            .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
        let published = slot.snapshot();
        assert!(!advance_wake_publication_is_unobserved(
            Some(initial.publish_gen),
            &published,
        ));

        assert!(!advance_wake_publication_is_unobserved(None, &initial));
    }

    #[test]
    fn advance_accepts_its_control_acknowledgement_and_later_serials() {
        let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
        let request = slot
            .request_control_boundary()
            .unwrap_or_else(|error| panic!("control request should publish: {error}"));
        slot.publish_control_boundary(0, 0, 0)
            .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
        slot.acknowledge_control_boundary();
        let acknowledged_with_publication = slot.snapshot();

        let mut later_acknowledgement = acknowledged_with_publication;
        later_acknowledgement.control_boundary_ack = request.wrapping_add(3);
        assert!(control_boundary_request_is_acknowledged(
            request,
            &later_acknowledgement,
        ));

        let mut stale_acknowledgement = acknowledged_with_publication;
        stale_acknowledgement.control_boundary_ack = request.wrapping_sub(1);
        assert!(!control_boundary_request_is_acknowledged(
            request,
            &stale_acknowledgement,
        ));
    }

    #[test]
    fn control_acknowledgement_order_wraps_without_accepting_stale_serials() {
        let mut snapshot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM).snapshot();
        snapshot.control_boundary_ack = 1;
        assert!(control_boundary_request_is_acknowledged(0, &snapshot));

        snapshot.control_boundary_ack = u32::MAX;
        assert!(!control_boundary_request_is_acknowledged(0, &snapshot));
    }

    #[test]
    fn completed_clamp_accepts_preserved_future_idle_deadline() {
        let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
        slot.arm_external_state_restore_ceiling(200)
            .unwrap_or_else(|error| panic!("idle ceiling should publish: {error}"));
        slot.publish_idle(40, 200, 0)
            .unwrap_or_else(|error| panic!("idle state should publish: {error}"));
        let snapshot = slot.snapshot();

        assert!(completed_quantum_clamp_is_settled(
            true, 40, 200, false, &snapshot,
        ));
        assert!(!completed_quantum_clamp_is_settled(
            true, 40, 40, false, &snapshot,
        ));
    }

    #[test]
    fn completed_clamp_rejects_unacknowledged_or_active_boundary() {
        let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
        let snapshot = slot.snapshot();

        assert!(completed_quantum_clamp_is_settled(
            true, 0, 0, false, &snapshot,
        ));
        assert!(!completed_quantum_clamp_is_settled(
            false, 0, 0, false, &snapshot,
        ));
        assert!(!completed_quantum_clamp_is_settled(
            true, 0, 0, true, &snapshot,
        ));
    }
}
