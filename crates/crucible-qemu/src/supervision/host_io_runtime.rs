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
    DequeuedFaultResult, MappedSetupRegion, STATUS_DONE, STATUS_IDLE, authorize_advance_ceiling,
    mmap_setup_region,
};

use super::accelerator_io_servicer::QemuLiveAcceleratorServicer;
use super::block_io_servicer::{BlockIoDiagnostics, QemuLiveBlockIoServicer};
use super::ninep_io_servicer::{NinepIoDiagnostics, QemuLive9pIoServicer};
use crate::console_observation::QemuConsoleObservationReader;
use crate::quantum::idle_state_from_snapshot;
use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{
    QemuAdvanceCompletionFence, QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome,
    QemuHostIoCheckpoint, QemuHostIoRuntime,
};
use deadline::AdvanceWaitDeadline;

mod boundary;
mod deadline;
use boundary::*;

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
    /// Pre-wake generation for scheduler input that invalidated an idle report.
    scheduler_input_publish_generation: Option<u32>,
    /// Plugin generation observed before host-serviced device work wakes QEMU.
    device_wake_publish_generation: Option<u32>,
    /// Zero-length idle coordinate left by an exact checkpoint pause.
    checkpoint_idle_coordinate: Option<u64>,
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
            scheduler_input_publish_generation: None,
            device_wake_publish_generation: None,
            checkpoint_idle_coordinate: None,
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
    /// Signals the plugin wake eventfd once before polling.
    ///
    /// Publishing the scheduler ceiling already wakes and orders the plugin's
    /// idle futex. A node parked at a later deterministic deadline therefore
    /// needs no additional main-loop acknowledgement: the published idle state
    /// remains a valid boundary for every smaller ceiling. Only device work
    /// serviced while polling can invalidate the observed state, so that path
    /// records the plugin generation and requires a later publication.
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
        let initial = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot();
        self.device_wake_publish_generation = None;
        self.checkpoint_idle_coordinate = checkpoint_idle_coordinate(&initial);
        if self.checkpoint_idle_coordinate.is_some() {
            // A QMP-resumed checkpoint retains the plugin's completed
            // all-halted edge. An acknowledged control boundary republishes
            // the coordinate and re-arms that edge before the fresh ceiling
            // may be classified; a bare doorbell cannot make that transition.
            let _request = self.signal_wake()?;
        } else {
            self.write_wake_doorbell()?;
        }
        self.repoll_advance_completion(timeout)
    }

    /// Polls for a quantum boundary after the initial plugin wake was sent.
    ///
    /// A host-serviced device transition rings the eventfd and records the
    /// preceding plugin generation. A later generation proves QEMU consumed
    /// that transition before the runtime accepts a boundary. The
    /// completed-quantum clamp performs a separate post-device control-token
    /// handshake before this runtime returns.
    fn repoll_advance_completion(
        &mut self,
        timeout: Duration,
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
                .scheduler_input_publish_generation
                .is_some_and(|generation| snapshot.publish_gen != generation)
            {
                self.scheduler_input_publish_generation = None;
            }
            if self
                .device_wake_publish_generation
                .is_some_and(|generation| snapshot.publish_gen != generation)
            {
                self.device_wake_publish_generation = None;
            }
            let checkpoint_idle_unreleased = checkpoint_idle_publication_is_unreleased(
                self.checkpoint_idle_coordinate,
                &snapshot,
            );
            if !checkpoint_idle_unreleased {
                self.checkpoint_idle_coordinate = None;
            }
            // Service block I/O before classifying the boundary: a guest blocked
            // on a probe read cannot reach the ceiling until its response is
            // delivered, so draining and delivering at the observed icount is what
            // lets the advance make progress.
            let block_progress = self.service_block_io(&snapshot)?;
            let ninep_progress = self.service_ninep_io(&snapshot)?;
            let accelerator_progress = self.service_accelerator_io(&snapshot)?;
            if (block_progress || ninep_progress || accelerator_progress)
                && self.device_wake_publish_generation.is_none()
            {
                self.device_wake_publish_generation = Some(snapshot.publish_gen);
            }
            self.publish_device_completion_deadline()?;
            let idle = idle_state_from_snapshot(snapshot);
            let wake_unacknowledged = device_wake_publication_is_unobserved(
                self.device_wake_publish_generation,
                &snapshot,
            );
            let scheduler_input_unobserved = device_wake_publication_is_unobserved(
                self.scheduler_input_publish_generation,
                &snapshot,
            );
            let boundary = if checkpoint_idle_unreleased {
                QuantumBoundary::Pending
            } else {
                classify_after_scheduler_and_host_wake(
                    &idle,
                    snapshot.max_advance_icount,
                    scheduler_input_unobserved,
                    wake_unacknowledged,
                )
            };
            match boundary {
                QuantumBoundary::Reached { .. } | QuantumBoundary::Paused { .. } => {
                    self.scheduler_input_publish_generation = None;
                    self.checkpoint_idle_coordinate = None;
                    self.clamp_completed_quantum(&snapshot, timeout)?;
                    self.service_console_output()?;
                    return Ok(QemuAsyncWaitOutcome::Completed);
                }
                QuantumBoundary::Pending => {
                    if snapshot.status == STATUS_DONE {
                        self.device_wake_publish_generation = None;
                        self.checkpoint_idle_coordinate = None;
                        return Ok(QemuAsyncWaitOutcome::Completed);
                    }
                    if self.device_wake_publish_generation.is_none() && attempt % 16 == 15 {
                        if checkpoint_idle_unreleased {
                            let _request = self.signal_wake()?;
                        } else {
                            self.write_wake_doorbell()?;
                        }
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
        timeout: Duration,
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
        // Boundary discovery and revocation acknowledgement are distinct
        // liveness phases. A quantum may consume nearly all of its discovery
        // budget under a heavily loaded TCG host; carrying only the residual
        // milliseconds into this mandatory odd-token handshake would make a
        // correct guest outcome depend on host contention. Give the handshake
        // its own bounded policy interval. Neither interval enters canonical
        // state or changes the exact guest coordinate.
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let mut last_observed_state = None;
        let mut boundary_acknowledged = false;
        let initial_idle_wake_icount = if snapshot.status == STATUS_IDLE {
            snapshot.idle_wake_icount
        } else {
            snapshot.current_icount
        };
        let mut device_progress_observed = false;
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
            device_progress_observed |= device_progress;
            let expected_idle_wake_icount = if device_progress_observed {
                snapshot.current_icount
            } else {
                initial_idle_wake_icount
            };
            last_observed_state = Some((
                observed.control_boundary_ack,
                observed.current_icount,
                observed.max_advance_icount,
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
            // before release-acknowledging the request. A node that retained a
            // future idle deadline may only tighten it. A node with no retained
            // future may immediately republish QEMU's fresh exact deadline from
            // its re-armed all-halted callback; accepting both states prevents
            // host observation timing from selecting liveness. Servicing device
            // work invalidates the retained deadline and requires another
            // observation after the current-coordinate fence.
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
                "QEMU did not publish the post-device control boundary within {timeout:?}: requested token {request}, expected current icount {}, retained-or-current idle wake icount {}, last observation {}",
                snapshot.current_icount,
                if device_progress_observed {
                    snapshot.current_icount
                } else {
                    initial_idle_wake_icount
                },
                last_observed_state.map_or_else(
                    || String::from("none"),
                    |(ack, current, max_advance, idle_wake, status, device_active, device_progress)| format!(
                        "token {ack}, current icount {current}, max advance icount {max_advance}, idle wake icount {idle_wake}, status {status}, device I/O active {device_active}, device progress {device_progress}",
                    ),
                )
            ),
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
    fn arm_advance_completion_fence(
        &mut self,
        fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scheduler_input_publish_generation =
            fence.map(|fence| fence.initial_publish_generation);
        Ok(())
    }

    fn checkpoint_device_io_is_quiescent(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot()
            .device_io_active
            == 0)
    }

    fn probe_checkpoint_device_io(
        &mut self,
        timeout: Duration,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "probe checkpoint device boundary",
                "checkpoint device probe timeout is zero",
            ));
        }
        let request = self.signal_wake()?;
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let mut last_observed = None;
        for attempt in 0..attempts {
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let block_progress = self.service_block_io(&snapshot)?;
            let ninep_progress = self.service_ninep_io(&snapshot)?;
            let accelerator_progress = self.service_accelerator_io(&snapshot)?;
            let device_progress = block_progress || ninep_progress || accelerator_progress;
            self.publish_device_completion_deadline()?;
            last_observed = Some((
                snapshot.control_boundary_ack,
                snapshot.current_icount,
                snapshot.device_io_active,
                device_progress,
            ));
            if control_boundary_request_is_acknowledged(request, &snapshot) {
                return Ok(!device_progress && snapshot.device_io_active == 0);
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "probe checkpoint device boundary",
            format!(
                "QEMU did not acknowledge control token {request} within {timeout:?}; last observation {}",
                last_observed.map_or_else(
                    || String::from("none"),
                    |(ack, current, active, progress)| format!(
                        "token {ack}, current icount {current}, device I/O active {active}, device progress {progress}"
                    ),
                )
            ),
        ))
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
        let mut deadline = AdvanceWaitDeadline::default();
        if !deadline.start(timeout) {
            return Err(QemuAsyncDriverRuntimeError::new(
                "quiesce for checkpoint",
                "checkpoint pause timeout exceeds the host supervision clock range",
            ));
        }
        let mut initial_snapshot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot();
        let reached_boundary_control_wake = initial_snapshot.status != STATUS_IDLE;

        if reached_boundary_control_wake {
            // Warm realization pulses the main-loop doorbell while connecting
            // QMP. Its final two-pass callback can still own QEMU's coalescing
            // token after the primer thread joins. Fence that ordinary control
            // work before publishing pause; otherwise the old callback can run
            // before pause is visible, clear the token, and strand the reached-
            // ceiling vCPU on its condition variable indefinitely.
            self.probe_checkpoint_device_io(timeout)?;
            initial_snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
        }
        let remaining = deadline.remaining().unwrap_or_default();
        if remaining.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "quiesce for checkpoint",
                "pre-pause control fence exhausted the checkpoint pause timeout",
            ));
        }
        let slot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?;
        let initial_publish_gen = initial_snapshot.publish_gen;
        if let Err(source) = self.region.header().request_pause([slot]) {
            return self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
                "request checkpoint pause",
                source.to_string(),
            ));
        }
        // Revoke the unused tail of the preceding quantum. Publishing this
        // ceiling also wakes the scheduler futex, so the plugin observes the
        // already-visible pause without a main-loop eventfd wake. A later
        // normal quantum must publish a fresh ceiling.
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
        let device_servicers_attached =
            self.block.is_some() || self.ninep.is_some() || self.accelerator.is_some();
        let zero_length_idle_control_wake = device_servicers_attached
            && initial_snapshot.status == STATUS_IDLE
            && initial_snapshot.idle_wake_icount == initial_snapshot.current_icount;
        let tokenized_checkpoint_control_wake =
            reached_boundary_control_wake || zero_length_idle_control_wake;
        if tokenized_checkpoint_control_wake
            || checkpoint_pause_requires_control_doorbell(
                &initial_snapshot,
                device_servicers_attached,
            )
        {
            // A reached-ceiling publication is parked on QEMU's condition
            // variable rather than the scheduler futex, so the clamped ceiling
            // cannot make it observe the pause. The pre-pause fence publishes
            // an idle-looking control boundary without changing that underlying
            // wait, so preserve the original reached-state provenance here.
            // Ring the main-loop doorbell in that state even with devices
            // attached: QEMU's two-pass control boundary orders any resulting
            // device bottom half before it publishes quiescence. An originally
            // idle device VM with a future deadline retains the stricter
            // no-doorbell path to avoid admitting a latent waiter. A zero-length
            // idle publication has no futex edge left to observe pause and uses
            // the same tokenized two-pass handoff as a reached boundary.
            let wake = if tokenized_checkpoint_control_wake {
                // The paired token makes a vCPU resume callback yield without
                // interpreting this control edge as guest authorization.
                self.signal_wake().map(|_request| ())
            } else {
                self.write_wake_doorbell()
            };
            if let Err(source) = wake {
                return self.fail_checkpoint_pause(source);
            }
        }
        let attempts = bounded_poll_attempts(remaining, self.poll_interval);
        let mut last_observed = None;
        for attempt in 0..attempts {
            let snapshot = match self.region.node_slot(self.vm_slot).map_err(map_slot_error) {
                Ok(slot) => slot.snapshot(),
                Err(source) => return self.fail_checkpoint_pause(source),
            };
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
            if let Err(source) = self.publish_device_completion_deadline() {
                return self.fail_checkpoint_pause(source);
            }
            // Servicing a device or publishing its next completion deadline can
            // wake QEMU and cause a fresh plugin boundary after `snapshot` was
            // read. Decide only from a post-service acquire snapshot; using the
            // stale pre-service state allowed checkpoint assembly to observe a
            // transient reached slot immediately after this method returned.
            let settled_snapshot = match self.region.node_slot(self.vm_slot).map_err(map_slot_error)
            {
                Ok(slot) => slot.snapshot(),
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            last_observed = Some((
                settled_snapshot.publish_gen,
                settled_snapshot.status,
                settled_snapshot.current_icount,
                settled_snapshot.idle_wake_icount,
                settled_snapshot.device_io_active,
                settled_snapshot.control_boundary_ack,
                self.region.header().pause_requested(),
            ));
            if settled_snapshot.publish_gen != initial_publish_gen
                && !device_progress
                && settled_snapshot.status == crucible_shmem::STATUS_IDLE
                && settled_snapshot.idle_wake_icount == settled_snapshot.current_icount
                && settled_snapshot.device_io_active == 0
            {
                // The plugin has queued native VM stop from the exact futex
                // callback. Wake QEMU's main loop so it can consume that
                // request and release the BQL to QMP. The patched block driver
                // suppresses request-coroutine wakeups while this stop is
                // pending, so the handoff cannot admit post-pause I/O.
                self.write_wake_doorbell()?;
                return Ok(());
            }
            if attempt + 1 < attempts {
                // Publishing the clamped ceiling already wakes the plugin's
                // scheduler futex. Do not ring the main-loop eventfd here: a
                // control-only wake can admit a latent block poll after the
                // readiness probe and create a future completion that cannot
                // retire at the frozen checkpoint coordinate. A reached
                // boundary is different: QMP-connect wake pulsing may have
                // consumed the coalesced callback token just before the pause
                // request. Re-publish its acknowledged token periodically so
                // coalescing cannot lose the required handoff.
                if tokenized_checkpoint_control_wake
                    && attempt % 16 == 15
                    && let Err(source) = self.signal_wake()
                {
                    return self.fail_checkpoint_pause(source);
                }
                thread::sleep(self.poll_interval);
            }
        }
        let detail = last_observed.map_or_else(
            || String::from("no node-slot snapshot was observed"),
            |(
                publish_gen,
                status,
                current_icount,
                idle_wake_icount,
                device_io_active,
                control_ack,
                pause_requested,
            )| {
                format!(
                    "initial publish generation {initial_publish_gen}, last publish generation {publish_gen}, status {status}, current icount {current_icount}, idle wake icount {idle_wake_icount}, device I/O active {device_io_active}, control serial {control_ack}, pause requested {pause_requested}"
                )
            },
        );
        self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
            "await checkpoint pause",
            format!("plugin did not acknowledge an exact boundary within {remaining:?}: {detail}"),
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
        payload_buffer: Vec<u8>,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.poll_fault_result(timeout, payload_buffer)
    }

    fn await_fault_preparation_result(
        &mut self,
        timeout: Duration,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.poll_fault_preparation_result(timeout)
    }
}

mod error;
pub use error::QemuLiveHostIoRuntimeError;
use error::map_slot_error;
mod fault_result;

#[cfg(test)]
#[path = "host_io_runtime_tests.rs"]
mod tests;
