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
mod checkpoint_pause;
mod control;
mod deadline;
mod device_service;
mod fingerprint_capture;
pub(crate) mod operational_wait;
mod performance;
use crucible_linux_resource::host_supervision::HostOperationClass;
use operational_wait::OperationPollBudget;
mod wait_observation;
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
    ram_control_registration: Option<crate::ram_control::RamControlRegistration>,
    host_operation_supervisor:
        Option<crucible_linux_resource::host_supervision::HostOperationSupervisor>,
    region: MappedSetupRegion,
    wake: Arc<File>,
    vm_slot: u32,
    poll_interval: Duration,
    performance: performance::PerformanceDiagnostics,
    wait_observation: wait_observation::WaitObservation,
    advance_wait_deadline: AdvanceWaitDeadline,
    /// Pre-wake generation for scheduler input that invalidated an idle report.
    scheduler_input_publish_generation: Option<u32>,
    /// Completion semantics armed with the current scheduler wake.
    advance_stop_condition: crate::QemuQuantumStopCondition,
    /// Plugin generation observed before host-serviced device work wakes QEMU.
    device_wake_publish_generation: Option<u32>,
    /// Zero-length idle coordinate left by an exact checkpoint pause.
    checkpoint_idle_coordinate: Option<u64>,
    /// Outbound producer frontier covered by the preceding completed quantum.
    completed_outbound_write_index: u64,
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
    launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
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
    fn private_hot_fork_ring_alias(
        &self,
        descriptor: BorrowedFd<'_>,
    ) -> Result<bool, rustix::io::Errno> {
        let metadata = rustix::fs::fstat(descriptor)?;
        let source = self.region.backing_identity();
        Ok(metadata.st_dev == source.device() && metadata.st_ino == source.inode())
    }

    fn validate_private_hot_fork_ring(
        &self,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let aliases = self
            .private_hot_fork_ring_alias(descriptor)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::new(
                    "clone hot-fork host-I/O continuation",
                    format!("cannot authenticate child ring identity: {error}"),
                )
            })?;
        if aliases {
            return Err(QemuAsyncDriverRuntimeError::new(
                "clone hot-fork host-I/O continuation",
                "child host-I/O ring aliases the retained source mapping",
            ));
        }
        Ok(())
    }

    pub(crate) fn with_launch_cleanup(
        mut self,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Self {
        self.launch_cleanup = cleanup;
        self
    }
    /// Retains the admitted RAM owner until all physical cleanup completes.
    #[must_use]
    pub fn with_ram_control_registration(
        mut self,
        registration: crate::ram_control::RamControlRegistration,
    ) -> Self {
        self.ram_control_registration = Some(registration);
        self
    }

    /// Attaches the execution owner's original-start live operation supervisor.
    #[must_use]
    pub fn with_host_operation_supervisor(
        mut self,
        supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Self {
        self.host_operation_supervisor = Some(supervisor);
        self
    }

    fn wait_for_poll_interval(&mut self, remaining: Duration) {
        self.performance.pending_sleep();
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
    /// the wake descriptor cannot be cloned, or
    /// [`QemuLiveHostIoRuntimeError::NetworkRing`] when the node's outbound
    /// network ring cannot be bound.
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
    /// [`QemuLiveHostIoRuntimeError::ZeroPollInterval`] when `poll_interval` is zero,
    /// or [`QemuLiveHostIoRuntimeError::NetworkRing`] when the node's outbound
    /// network ring cannot be bound.
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
        let mut region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveHostIoRuntimeError::MapRegion { source })?;
        let completed_outbound_write_index = region
            .node_directed_ring_pair_mut(
                vm_slot,
                vm_slot,
                crucible_shmem::SLOT_NET_ROUTER as u32,
                crucible_shmem::SLOT_NET_ROUTER as u32,
                vm_slot,
            )
            .map_err(|source| QemuLiveHostIoRuntimeError::NetworkRing { source })?
            .first
            .header
            .write_index();
        let wake = wake_fd
            .try_clone_to_owned()
            .map(File::from)
            .map_err(|source| QemuLiveHostIoRuntimeError::CloneWakeFd { source })?;
        Ok(Self {
            region,
            wake: Arc::new(wake),
            vm_slot,
            poll_interval,
            host_operation_supervisor: None,
            ram_control_registration: None,
            performance: performance::PerformanceDiagnostics::from_environment(shmem_fd),
            wait_observation: wait_observation::WaitObservation::from_environment(shmem_fd),
            advance_wait_deadline: AdvanceWaitDeadline::default(),
            scheduler_input_publish_generation: None,
            advance_stop_condition: crate::QemuQuantumStopCondition::Ceiling,
            device_wake_publish_generation: None,
            checkpoint_idle_coordinate: None,
            completed_outbound_write_index,
            block: None,
            ninep: None,
            accelerator: None,
            console: None,
            staged_fault_events: Vec::new(),
            fault_event_staging_limit: HARD_FAULT_EVENT_CAPACITY as usize,
            fault_event_canonical_current_offset: 0,
            fault_event_configured_limit: HARD_FAULT_EVENT_CAPACITY as usize,
            launch_cleanup: None,
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
        self.poll_advance_completion_with_original(timeout, None)
    }

    fn poll_advance_completion_with_original(
        &mut self,
        timeout: Duration,
        original: Option<&crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let deadline = original
            .map(|guard| OperationPollBudget::borrow_original(guard, "original quantum wake"))
            .transpose()?;
        if original.is_none() && !self.advance_wait_deadline.start(timeout) {
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
        self.wait_observation.begin(timeout);
        self.device_wake_publish_generation = None;
        self.checkpoint_idle_coordinate = checkpoint_idle_coordinate(&initial);
        if let Some(deadline) = &deadline {
            deadline.complete("original quantum wake")?;
        }
        if self.checkpoint_idle_coordinate.is_some() {
            // A QMP-resumed checkpoint retains the plugin's completed
            // all-halted edge. An acknowledged control boundary republishes
            // the coordinate and re-arms that edge before the fresh ceiling
            // may be classified; a bare doorbell cannot make that transition.
            let _request = self.signal_wake(None)?;
        } else {
            self.write_wake_doorbell()?;
        }
        if let Some(deadline) = &deadline {
            deadline.complete("original quantum wake")?;
        }
        self.repoll_advance_completion_with_original(timeout, original)
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
        self.repoll_advance_completion_with_original(timeout, None)
    }

    fn repoll_advance_completion_with_original(
        &mut self,
        timeout: Duration,
        original: Option<&crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let deadline = original
            .map(|guard| OperationPollBudget::borrow_original(guard, "original quantum poll"))
            .transpose()?;
        let remaining = match &deadline {
            Some(deadline) => deadline.remaining("original quantum poll")?,
            None => self.advance_wait_deadline.remaining(),
        }
        .ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "repoll advance completion",
                "initial await did not establish a deadline",
            )
        })?;
        self.wait_observation.observe_remaining(remaining);
        if remaining.is_zero() {
            return Ok(QemuAsyncWaitOutcome::TimedOut);
        }
        let attempts = bounded_poll_attempts(remaining, self.poll_interval);
        for attempt in 0..attempts {
            let remaining = match &deadline {
                Some(deadline) => deadline.remaining("original quantum poll")?,
                None => self.advance_wait_deadline.remaining(),
            }
            .ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new(
                    "repoll advance completion",
                    "initial await did not establish a deadline",
                )
            })?;
            self.wait_observation.observe_remaining(remaining);
            if remaining.is_zero() {
                return Ok(QemuAsyncWaitOutcome::TimedOut);
            }

            if let Some(deadline) = &deadline {
                deadline.complete("original quantum poll")?;
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
            let output_stop = self.network_output_stop_write_index(&snapshot)?;
            let checkpoint_idle_unreleased = output_stop.is_none()
                && checkpoint_idle_publication_is_unreleased(
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
            if let Some(deadline) = &deadline {
                deadline.complete("original quantum poll")?;
            }
            let block_progress = self.service_block_io(&snapshot)?;
            if let Some(deadline) = &deadline {
                deadline.complete("original quantum poll")?;
            }
            let ninep_progress = self.service_ninep_io(&snapshot)?;
            if let Some(deadline) = &deadline {
                deadline.complete("original quantum poll")?;
            }
            let accelerator_progress = self.service_accelerator_io(&snapshot)?;
            if (block_progress || ninep_progress || accelerator_progress)
                && self.device_wake_publish_generation.is_none()
            {
                self.device_wake_publish_generation = Some(snapshot.publish_gen);
            }
            if let Some(deadline) = &deadline {
                deadline.complete("original quantum poll")?;
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
                    self.clamp_completed_quantum_with_original(&snapshot, timeout, original)?;
                    self.completed_outbound_write_index = self.outbound_write_index()?;
                    if let Some(deadline) = &deadline {
                        deadline.complete("original quantum poll")?;
                    }
                    self.service_console_output()?;
                    if let Some(deadline) = &deadline {
                        deadline.complete("original quantum poll")?;
                    }
                    return Ok(QemuAsyncWaitOutcome::Completed);
                }
                QuantumBoundary::Pending => {
                    if snapshot.status == STATUS_DONE {
                        self.device_wake_publish_generation = None;
                        self.checkpoint_idle_coordinate = None;
                        if let Some(deadline) = &deadline {
                            deadline.complete("original quantum poll")?;
                        }
                        return Ok(QemuAsyncWaitOutcome::Completed);
                    }
                    if self.device_wake_publish_generation.is_none() && attempt % 16 == 15 {
                        if let Some(deadline) = &deadline {
                            deadline.complete("original quantum poll")?;
                        }
                        if checkpoint_idle_unreleased {
                            let _request = self.signal_wake(None)?;
                        } else {
                            self.write_wake_doorbell()?;
                        }
                    }
                }
            }
            if attempt + 1 < attempts {
                let remaining = match &deadline {
                    Some(deadline) => deadline.remaining("original quantum poll")?,
                    None => self.advance_wait_deadline.remaining(),
                }
                .ok_or_else(|| {
                    QemuAsyncDriverRuntimeError::new(
                        "repoll advance completion",
                        "initial await did not establish a deadline",
                    )
                })?;
                self.wait_observation.observe_remaining(remaining);
                if remaining.is_zero() {
                    return Ok(QemuAsyncWaitOutcome::TimedOut);
                }
                self.observe_pending_wait("advance-pending", &snapshot, None, remaining);
                if let Some(deadline) = &deadline {
                    self.performance.pending_sleep();
                    deadline.wait(self.poll_interval, "original quantum poll")?;
                } else {
                    self.wait_for_poll_interval(remaining);
                }
            }
        }
        Ok(QemuAsyncWaitOutcome::TimedOut)
    }
}

impl Drop for QemuLiveHostIoRuntime {
    fn drop(&mut self) {
        let Some(cleanup) = &self.launch_cleanup else {
            return;
        };
        if !cleanup.is_published() || !cleanup.cleanup_proven() {
            return;
        }
        if let Some(registration) = &self.ram_control_registration {
            // Node fields reap the child and join its source before this
            // runtime drops. Closing registry custody releases no capacity;
            // final cleanup custody follows local descriptor/lease disposal.
            let _ = registration
                .registrar
                .prepare_retirement_after_cleanup(registration.target);
        }
    }
}

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
fn reader_probe_error(message: impl Into<String>) -> crate::QemuNodeChannelError {
    crate::QemuNodeChannelError::new("probe retained host reader ownership", message)
}

impl QemuHostIoRuntime for QemuLiveHostIoRuntime {
    fn ram_control_registration(&self) -> Option<&crate::ram_control::RamControlRegistration> {
        self.ram_control_registration.as_ref()
    }

    #[cfg(any(test, feature = "test-support"))]
    fn host_service_allocator_for_test(
        &self,
    ) -> Option<crucible_linux_resource::host_services::HostServiceAllocator> {
        self.ram_control_registration
            .as_ref()
            .map(|registration| registration.host_services.clone())
    }

    #[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
    fn probe_hot_fork_reader_alias_for_test(
        &mut self,
        descriptor: BorrowedFd<'_>,
        ninep: bool,
    ) -> Result<crate::QemuNodeChannelError, crate::QemuNodeChannelError> {
        if ninep {
            let servicer = self
                .ninep
                .as_ref()
                .ok_or_else(|| reader_probe_error("source has no actual 9p reader"))?;
            return match servicer
                .servicer
                .validate_private_hot_fork_reader(descriptor)
            {
                Err(
                    error @ super::ninep_io_servicer::QemuLive9pIoServicerError::SourceMappingAlias,
                ) => Ok(reader_probe_error(error.to_string())),
                Err(error) => Err(reader_probe_error(error.to_string())),
                Ok(()) => Err(reader_probe_error("9p reader accepted the source mapping")),
            };
        }

        if !self
            .private_hot_fork_ring_alias(descriptor)
            .map_err(|error| reader_probe_error(error.to_string()))?
        {
            return Err(reader_probe_error(
                "network continuation candidate is not the source mapping",
            ));
        }
        match self.validate_private_hot_fork_ring(descriptor) {
            Err(error) => Ok(reader_probe_error(error.to_string())),
            Ok(()) => Err(reader_probe_error(
                "network continuation accepted the source mapping",
            )),
        }
    }

    fn reserve_fault_manifest_metadata(
        &self,
        bytes: u64,
    ) -> Result<crate::QemuFaultManifestMetadataLease, QemuAsyncDriverRuntimeError> {
        let registration = self.ram_control_registration.as_ref().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "reserve fault manifest metadata",
                "runtime has no admitted node service allocator",
            )
        })?;
        let cleanup = self.launch_cleanup.as_ref().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "reserve fault manifest metadata",
                "runtime has no retained native cleanup authority",
            )
        })?;
        if bytes == 0 {
            return Err(QemuAsyncDriverRuntimeError::new(
                "reserve fault manifest metadata",
                "metadata request is empty",
            ));
        }
        let charged = bytes
            .checked_add(crucible_linux_resource::host_services::HostServiceLease::metadata_bytes())
            .ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new(
                    "reserve fault manifest metadata",
                    "metadata loan accounting overflows",
                )
            })?;
        let service = registration
            .host_services
            .reserve_resources(0, 0, charged)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::new(
                    "reserve fault manifest metadata",
                    error.to_string(),
                )
            })?;
        Ok(crate::QemuFaultManifestMetadataLease::new(
            service,
            cleanup.clone(),
        ))
    }

    fn retire_host_ram_after_cleanup(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        if self
            .launch_cleanup
            .as_ref()
            .is_some_and(|cleanup| !cleanup.is_published())
        {
            return Ok(());
        }
        let Some(registration) = &self.ram_control_registration else {
            return Ok(());
        };
        let supervisor = self.host_operation_supervisor.as_ref().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "retire host RAM resources",
                "registered RAM owner has no live cleanup supervisor",
            )
        })?;
        let cleanup = supervisor
            .begin(crucible_linux_resource::host_supervision::HostOperationClass::Cleanup)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "retire host RAM resources",
                    error,
                )
            })?;
        loop {
            cleanup.wait_slice().map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "retire host RAM resources",
                    error,
                )
            })?;
            if registration
                .registrar
                .prepare_retirement_after_cleanup(registration.target)
                .is_ok()
            {
                cleanup.complete().map_err(|error| {
                    QemuAsyncDriverRuntimeError::operational_supervision(
                        "retire host RAM resources",
                        error,
                    )
                })?;
                self.ram_control_registration = None;
                return Ok(());
            }
            cleanup.wait_for_change().map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "retire host RAM resources",
                    error,
                )
            })?;
        }
    }

    fn set_host_operation_supervisor(
        &mut self,
        supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.host_operation_supervisor = Some(supervisor);
        Ok(())
    }

    fn host_operation_supervisor(
        &self,
    ) -> Option<&crucible_linux_resource::host_supervision::HostOperationSupervisor> {
        self.host_operation_supervisor.as_ref()
    }

    fn renew_advance_completion_poll(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if self.advance_wait_deadline.start(timeout) {
            // The async driver renews after TimedOut to check child liveness.
            // Count only budget consumption already observed by that poll;
            // early renewal cannot manufacture diagnostic elapsed time.
            self.wait_observation.renew(timeout);
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "renew advance completion poll",
                "timeout deadline overflow",
            ))
        }
    }

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
        self.validate_private_hot_fork_ring(shmem_fd)?;
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
        self.performance.arm();
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
        let deadline = OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            HostOperationClass::Quiescence,
            timeout,
            "probe checkpoint device boundary",
        )?;
        self.probe_checkpoint_device_boundary(&deadline, timeout)
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let deadline = OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            HostOperationClass::FingerprintUpdate,
            timeout,
            "publish current execution fingerprint",
        )?;

        let request = self
            .region
            .fingerprint_sample(self.vm_slot)
            .map_err(map_slot_error)?
            .request_capture_v1();
        self.capture_execution_fingerprint(&deadline, timeout, request)
    }

    fn publish_current_execution_fingerprint_under_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let operation = "publish current execution fingerprint";
        let deadline = OperationPollBudget::borrow_original(original, operation)?;
        let remaining = deadline.remaining(operation)?.ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(operation, "original operation has expired")
        })?;
        let request = self
            .region
            .fingerprint_sample(self.vm_slot)
            .map_err(map_slot_error)?
            .request_fresh_capture_v1()
            .map_err(|source| QemuAsyncDriverRuntimeError::new(operation, source.to_string()))?;
        self.capture_execution_fingerprint(&deadline, remaining, request)
    }

    /// Requests an exact plugin boundary and hands QEMU's execution path to QMP.
    fn quiesce_for_checkpoint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let deadline = OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            HostOperationClass::Quiescence,
            timeout,
            "quiesce for checkpoint",
        )?;
        self.pause_checkpoint_boundary(&deadline, timeout, None)
    }

    fn quiesce_for_checkpoint_under_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let operation = "quiesce for checkpoint";
        let deadline = OperationPollBudget::borrow_original(original, operation)?;
        let remaining = deadline.remaining(operation)?.ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(operation, "original operation has expired")
        })?;
        self.pause_checkpoint_boundary(&deadline, remaining, Some(original))
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

    fn await_child_under_original(
        &mut self,
        wait: QemuAsyncWait,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        if wait != QemuAsyncWait::AdvanceCompletion {
            return Err(QemuAsyncDriverRuntimeError::new(
                "original quantum wait",
                "unsupported wait class",
            ));
        }
        let deadline = OperationPollBudget::borrow_original(original, "original quantum wait")?;
        let timeout = deadline
            .remaining("original quantum wait")?
            .ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new("original quantum wait", "expired original")
            })?;
        self.poll_advance_completion_with_original(timeout, Some(original))
    }

    fn repoll_child_under_original(
        &mut self,
        wait: QemuAsyncWait,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        if wait != QemuAsyncWait::AdvanceCompletion {
            return Err(QemuAsyncDriverRuntimeError::new(
                "original quantum repoll",
                "unsupported wait class",
            ));
        }
        let deadline = OperationPollBudget::borrow_original(original, "original quantum repoll")?;
        let timeout = deadline
            .remaining("original quantum repoll")?
            .ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new("original quantum repoll", "expired original")
            })?;
        self.repoll_advance_completion_with_original(timeout, Some(original))
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
