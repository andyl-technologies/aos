//! Production host-I/O runtime for a live QEMU node.
//!
//! [`QemuLiveHostIoRuntime`] maps the hot-path channel's `MAP_SHARED` descriptor.
//! On an `AdvanceCompletion` await, it signals QEMU's plugin wake eventfd and
//! polls the node slot through the shared [`classify_quantum_boundary`] decision.
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
//!
//! At a retained-template hot fork, the runtime checkpoints its quiescent
//! block, 9p, and deterministic accelerator state and reconstructs independent
//! devices over the child's already-imaged private setup region. Source
//! signal-coordinator capabilities are never shared across worlds; the child
//! retains only the requirement for a fresh branch-local coordinator.

use std::fs::File;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crucible::model::ContentHash;
use crucible_shmem::{
    DequeuedFaultEvent, DequeuedFaultResult, HARD_FAULT_EVENT_CAPACITY, MappedSetupRegion,
    STATUS_DONE, STATUS_IDLE, authorize_advance_ceiling, mmap_setup_region,
};

use super::accelerator_io_servicer::QemuLiveAcceleratorServicer;
use super::block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoServicer,
};
use super::ninep_io_servicer::{NinepIoDiagnostics, QemuLive9pIoServicer};
use crate::console_observation::QemuConsoleObservationReader;
use crate::quantum::idle_state_from_snapshot;
use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::supervision::HostSupervisionDeadline;
use crate::{
    QemuAdvanceCompletionFence, QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome,
    QemuHostIoCheckpoint, QemuHostIoRuntime,
};
use deadline::{AdvanceWaitDeadline, DEFAULT_POLL_INTERVAL};

mod boundary;
mod control;
mod deadline;
mod device_service;
use boundary::*;

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
    /// Completion semantics armed with the current scheduler wake.
    advance_stop_condition: crate::QemuQuantumStopCondition,
    /// Plugin generation observed before host-serviced device work wakes QEMU.
    device_wake_publish_generation: Option<u32>,
    /// Zero-length idle coordinate left by an exact checkpoint pause.
    checkpoint_idle_coordinate: Option<u64>,
    block: Option<BlockIoServicing>,
    ninep: Option<NinepIoServicing>,
    accelerator: Option<QemuLiveAcceleratorServicer>,
    console: Option<QemuConsoleObservationReader>,
    /// Events physically consumed to release a fault-pump control fence.
    staged_fault_events: Vec<DequeuedFaultEvent>,
    /// Plan-authored remaining aggregate capacity for staged events.
    fault_event_staging_limit: usize,
    /// Canonical records owned outside this runtime's local staging vector.
    fault_event_canonical_current_offset: usize,
    /// Plan-authored aggregate event-record ceiling reported by LIMIT-2.
    fault_event_configured_limit: usize,
}

mod servicing;
use servicing::{BlockIoServicing, NinepIoServicing};

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
    fn wait_for_poll_interval(&self, remaining: Duration) {
        thread::sleep(self.poll_interval.min(remaining));
    }

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
            advance_stop_condition: crate::QemuQuantumStopCondition::Ceiling,
            device_wake_publish_generation: None,
            checkpoint_idle_coordinate: None,
            block: None,
            ninep: None,
            accelerator: None,
            console: None,
            staged_fault_events: Vec::new(),
            fault_event_staging_limit: HARD_FAULT_EVENT_CAPACITY as usize,
            fault_event_canonical_current_offset: 0,
            fault_event_configured_limit: HARD_FAULT_EVENT_CAPACITY as usize,
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
        let (worker, servicer) = super::QemuLiveBlockHostWorkPool::from_servicer(servicer)
            .map_err(|source| super::QemuLiveBlockIoServicerError::HostWorker {
                message: source.to_string(),
            })?;
        self.block = Some(BlockIoServicing {
            servicer,
            worker,
            diagnostics,
            coordinator_required: false,
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
            coordinator_required: false,
        });
        self
    }

    /// Attaches the production deterministic accelerator adapter.
    #[must_use]
    pub fn with_accelerator_servicer(mut self, servicer: QemuLiveAcceleratorServicer) -> Self {
        self.accelerator = Some(servicer);
        self
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
            let _request = self.signal_wake(None)?;
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
            let remaining = self.advance_wait_deadline.remaining().ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new(
                    "repoll advance completion",
                    "initial await did not establish a deadline",
                )
            })?;
            if remaining.is_zero() {
                return Ok(QemuAsyncWaitOutcome::TimedOut);
            }

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
                    self.advance_stop_condition,
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
                            let _request = self.signal_wake(None)?;
                        } else {
                            self.write_wake_doorbell()?;
                        }
                    }
                }
            }
            if attempt + 1 < attempts {
                let remaining = self.advance_wait_deadline.remaining().ok_or_else(|| {
                    QemuAsyncDriverRuntimeError::new(
                        "repoll advance completion",
                        "initial await did not establish a deadline",
                    )
                })?;
                if remaining.is_zero() {
                    return Ok(QemuAsyncWaitOutcome::TimedOut);
                }
                self.wait_for_poll_interval(remaining);
            }
        }
        Ok(QemuAsyncWaitOutcome::TimedOut)
    }
}

impl QemuHostIoRuntime for QemuLiveHostIoRuntime {
    #[cfg(test)]
    fn service_ninep_io_for_test(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.service_ninep_io(snapshot)
    }

    fn clone_hot_fork_host_io_continuation(
        &mut self,
        execution_binding: ContentHash,
        shmem_fd: BorrowedFd<'_>,
        wake_fd: BorrowedFd<'_>,
        region_len: u64,
        console: Option<crate::QemuHotForkChildConsoleObservation>,
    ) -> Result<Box<dyn QemuHostIoRuntime>, QemuAsyncDriverRuntimeError> {
        if self.console.is_some() != console.is_some() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "clone hot-fork host-I/O continuation",
                "source and child console observation capabilities differ",
            ));
        }
        if self.scheduler_input_publish_generation.is_some()
            || self.device_wake_publish_generation.is_some()
        {
            return Err(QemuAsyncDriverRuntimeError::new(
                "clone hot-fork host-I/O continuation",
                "scheduler or device publication remains unsettled",
            ));
        }
        if self
            .region
            .fingerprint_sample(self.vm_slot)
            .map_err(map_slot_error)?
            .pending_capture_request_v1()
            .is_some()
        {
            return Err(QemuAsyncDriverRuntimeError::new(
                "clone hot-fork host-I/O continuation",
                "on-demand fingerprint capture request remains pending",
            ));
        }

        let block = self
            .block
            .as_mut()
            .map(|block| -> Result<_, QemuAsyncDriverRuntimeError> {
                block
                    .lock_servicer("clone hot-fork block continuation")?
                    .clone_hot_fork_continuation(shmem_fd, region_len, execution_binding)
                    .map(|servicer| (servicer, block.coordinator_required))
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "clone hot-fork block continuation",
                            source.to_string(),
                        )
                    })
            })
            .transpose()?;
        let ninep = self
            .ninep
            .as_mut()
            .map(|ninep| {
                ninep
                    .servicer
                    .clone_hot_fork_continuation(shmem_fd, region_len, execution_binding)
                    .map(|servicer| (servicer, ninep.coordinator_required))
            })
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "clone hot-fork 9p continuation",
                    source.to_string(),
                )
            })?;
        let accelerator = self
            .accelerator
            .as_ref()
            .map(|accelerator| accelerator.clone_hot_fork_continuation(shmem_fd, region_len))
            .transpose()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "clone hot-fork accelerator continuation",
                    source.to_string(),
                )
            })?;

        let mut continuation = Self::from_shmem_fd_with_poll_interval(
            shmem_fd,
            wake_fd,
            region_len,
            self.vm_slot,
            self.poll_interval,
        )
        .map_err(|source| {
            QemuAsyncDriverRuntimeError::new("clone hot-fork host-I/O runtime", source.to_string())
        })?;
        continuation.checkpoint_idle_coordinate = self.checkpoint_idle_coordinate;
        continuation.staged_fault_events = self.staged_fault_events.clone();
        continuation.fault_event_staging_limit = self.fault_event_staging_limit;
        continuation.fault_event_canonical_current_offset =
            self.fault_event_canonical_current_offset;
        continuation.fault_event_configured_limit = self.fault_event_configured_limit;
        continuation.console = console.map(crate::QemuHotForkChildConsoleObservation::into_reader);
        if let Some((servicer, coordinator_required)) = block {
            servicer
                .shared_device()
                .attach_notification_wake(Arc::clone(&continuation.wake))
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "attach hot-fork block notification",
                        source.to_string(),
                    )
                })?;
            let (worker, servicer) = super::QemuLiveBlockHostWorkPool::from_servicer(servicer)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "start hot-fork block host worker",
                        source.to_string(),
                    )
                })?;
            continuation.block = Some(BlockIoServicing {
                servicer,
                worker,
                diagnostics: BlockIoDiagnostics::shared(),
                coordinator_required,
            });
        }
        if let Some((servicer, coordinator_required)) = ninep {
            continuation.ninep = Some(NinepIoServicing {
                servicer,
                diagnostics: NinepIoDiagnostics::shared(),
                coordinator: None,
                coordinator_required,
            });
        }
        continuation.accelerator = accelerator;
        Ok(Box::new(continuation))
    }

    fn set_fault_event_staging_limit(
        &mut self,
        maximum_local_records: usize,
        canonical_current_offset: usize,
        configured_event_records: usize,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let current = self.staged_fault_events.len();
        if current > maximum_local_records {
            return Err(QemuAsyncDriverRuntimeError::fault_event_storage(
                canonical_current_offset.saturating_add(current),
                0,
                configured_event_records,
            ));
        }
        self.fault_event_staging_limit = maximum_local_records;
        self.fault_event_canonical_current_offset = canonical_current_offset;
        self.fault_event_configured_limit = configured_event_records;
        Ok(())
    }

    fn arm_advance_completion_fence(
        &mut self,
        fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scheduler_input_publish_generation =
            fence.map(|fence| fence.initial_publish_generation);
        self.advance_stop_condition = fence
            .map(|fence| fence.stop_condition)
            .unwrap_or(crate::QemuQuantumStopCondition::Ceiling);
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
        let request = self.signal_wake(None)?;
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let deadline = HostSupervisionDeadline::start(timeout);
        let mut last_observed = None;
        for attempt in 0..attempts {
            if !deadline.has_time_remaining() {
                break;
            }

            self.drain_fault_events_for_pump(
                self.fault_event_staging_limit,
                &deadline,
                timeout,
                "probe checkpoint device boundary",
            )?;
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
                let Some(remaining) = deadline.remaining() else {
                    break;
                };
                self.wait_for_poll_interval(remaining);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "probe checkpoint device boundary",
            format!(
                "QEMU did not acknowledge control token {} within {timeout:?}; last observation {}",
                request.generation,
                last_observed.map_or_else(
                    || String::from("none"),
                    |(ack, current, active, progress)| format!(
                        "token {ack}, current icount {current}, device I/O active {active}, device progress {progress}"
                    ),
                )
            ),
        ))
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "publish current execution fingerprint",
                "execution fingerprint control-boundary timeout is zero",
            ));
        }

        let fingerprint_request = self
            .region
            .fingerprint_sample(self.vm_slot)
            .map_err(map_slot_error)?
            .request_capture_v1();
        let fingerprint_acknowledgement = fingerprint_request.wrapping_add(1);
        let request = self.signal_wake(Some(fingerprint_request))?;
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let deadline = HostSupervisionDeadline::start(timeout);
        let mut last_observed = None;
        for attempt in 0..attempts {
            if !deadline.has_time_remaining() {
                break;
            }

            self.drain_fault_events_for_pump(
                self.fault_event_staging_limit,
                &deadline,
                timeout,
                "publish current execution fingerprint",
            )?;
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let fingerprint_ack = self
                .region
                .fingerprint_sample(self.vm_slot)
                .map_err(map_slot_error)?
                .capture_request_generation();
            last_observed = Some((
                snapshot.control_boundary_ack,
                snapshot.current_icount,
                snapshot.status,
                fingerprint_ack,
            ));
            if control_boundary_request_is_acknowledged(request, &snapshot) {
                if fingerprint_ack == fingerprint_acknowledgement {
                    // The digest worker publishes the sample before its release
                    // acknowledgement. This acquire load therefore makes the
                    // exact sample visible through the independent mapping.
                    return Ok(());
                }
                if fingerprint_ack != fingerprint_request {
                    return Err(QemuAsyncDriverRuntimeError::new(
                        "publish current execution fingerprint",
                        format!(
                            "plugin acknowledged control token {} for fingerprint request {fingerprint_request}, but observed unrelated fingerprint generation {fingerprint_ack}",
                            request.generation,
                        ),
                    ));
                }
            }
            if attempt + 1 < attempts {
                let Some(remaining) = deadline.remaining() else {
                    break;
                };
                if attempt % 16 == 15 {
                    self.write_wake_doorbell()?;
                }
                self.wait_for_poll_interval(remaining);
            }
        }

        Err(QemuAsyncDriverRuntimeError::new(
            "publish current execution fingerprint",
            format!(
                "QEMU did not acknowledge fingerprint control token {} within {timeout:?}; last observation {}",
                request.generation,
                last_observed.map_or_else(
                    || String::from("none"),
                    |(ack, current, status, fingerprint)| {
                        format!(
                            "token {ack}, current icount {current}, status {status}, fingerprint generation {fingerprint}"
                        )
                    },
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
        if let Err(source) = slot.publish_scheduler_advance(
            checkpoint_ceiling,
            crucible_shmem::AdvanceStopCondition::Ceiling,
        ) {
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
                self.signal_wake(None).map(|_request| ())
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
            if !deadline
                .remaining()
                .is_some_and(|remaining| !remaining.is_zero())
            {
                break;
            }

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
                let Some(remaining) = deadline.remaining() else {
                    break;
                };
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
                    && let Err(source) = self.signal_wake(None)
                {
                    return self.fail_checkpoint_pause(source);
                }
                self.wait_for_poll_interval(remaining);
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
            .as_ref()
            .map(|block| {
                block
                    .lock_servicer("inspect pending block I/O")?
                    .has_pending_work()
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "inspect pending block I/O",
                            source.to_string(),
                        )
                    })
            })
            .transpose()
            .map(Option::unwrap_or_default)?;
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
            .as_ref()
            .map(|block| {
                block
                    .lock_servicer("checkpoint host block I/O")?
                    .checkpoint(execution_binding)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "checkpoint host block I/O",
                            source.to_string(),
                        )
                    })
            })
            .transpose()?;
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
                .lock_servicer("validate host block-I/O checkpoint")?
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
            .as_ref()
            .map(|block| {
                block
                    .lock_servicer("capture block rollback checkpoint")?
                    .checkpoint(execution_binding)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "capture block rollback checkpoint",
                            source.to_string(),
                        )
                    })
            })
            .transpose()?;
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
                .lock_servicer("restore host block-I/O checkpoint")?
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
                    .lock_servicer("roll back host block-I/O checkpoint")?
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
                && let Err(rollback) = block
                    .lock_servicer("roll back aggregate block checkpoint")?
                    .restore_checkpoint(execution_binding, prior)
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
                block
                    .lock_servicer("capture block boundary state")?
                    .storage_fault_state()
                    .map_err(|source| {
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
            .map(|block| block.worker.shared_device())
    }

    fn block_io_diagnostics(&self) -> Option<BlockIoDiagnosticsSnapshot> {
        self.block
            .as_ref()
            .map(|block| block.diagnostics.snapshot())
    }

    fn restore_block_boundary_state(
        &mut self,
        state: Option<crucible_device::block::BlockFaultState>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match (self.block.as_mut(), state) {
            (Some(block), Some(state)) => {
                block
                    .lock_servicer("restore block boundary state")?
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
        block
            .worker
            .apply_boundary_actions(coordinate, evaluation_sequence, actions.to_vec())
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("apply block boundary actions", source.to_string())
            })
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
        block
            .worker
            .install_fault_coordinator(coordinator)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "install block fault coordinator",
                    source.to_string(),
                )
            })?;
        block.coordinator_required = true;
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
        ninep.coordinator_required = true;
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
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.poll_fault_result(timeout, payload_buffer, maximum_event_records)
    }

    fn await_fault_preparation_result(
        &mut self,
        timeout: Duration,
        maximum_payload_bytes: usize,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.poll_fault_preparation_result(timeout, maximum_payload_bytes, maximum_event_records)
    }

    fn take_staged_fault_events(
        &mut self,
    ) -> Result<Vec<DequeuedFaultEvent>, QemuAsyncDriverRuntimeError> {
        Ok(std::mem::take(&mut self.staged_fault_events))
    }

    fn staged_fault_events(&self) -> &[DequeuedFaultEvent] {
        &self.staged_fault_events
    }

    fn staged_fault_events_pending(&self) -> bool {
        !self.staged_fault_events.is_empty()
    }

    fn staged_fault_event_count(&self) -> usize {
        self.staged_fault_events.len()
    }
}

mod error;
pub use error::QemuLiveHostIoRuntimeError;
use error::map_slot_error;
mod fault_result;

#[cfg(test)]
#[path = "host_io_runtime_tests.rs"]
pub(crate) mod tests;
