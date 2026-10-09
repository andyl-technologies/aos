//! Stopped private-child console handoff before its first scheduler grant.
//!
//! The original typed fork basis and process-free canonical continuation stay
//! owned through fresh capability admission and paired Restore. These local
//! receipts publish no native permission; the child INITIALIZE/CLOSED owners
//! and exact public ACK/frontier independently complete that transition.

use std::os::fd::OwnedFd;

use crate::supervision::HostSupervisionAbsoluteDeadline;

use super::*;
use crate::native_console_owner::{
    ConsoleLaunchCustody, ConsoleOriginContinuation, ConsoleOwnerError,
};

/// Opaque captured child inputs borrowed by the actual mapped channel.
///
/// This value has no constructor from raw public fields. It retains the
/// original fork request, private descriptor and captured logical custody;
/// neither the descriptor nor canonical bytes authenticate a native phase.
#[derive(Debug)]
pub struct QemuHotForkConsoleAdmission {
    pub(crate) request: crate::QmpHotForkRequest,
    pub(crate) descriptor: OwnedFd,
    pub(crate) saved: ConsoleOriginContinuation,
    pub(crate) calibration: QemuLogicalTimeCalibration,
    pub(crate) deadline: HostSupervisionAbsoluteDeadline,
    pub(crate) stopped_restore_ack: crate::QemuStoppedRestoreAckCapability,
}

/// Linear stopped Restore custody retained until exact child acceptance.
///
/// A failed wake or bounded wait leaves the original request and full issued
/// body owned here. No fresh Cold constructor or independent request getter
/// can replace this handoff, and no guest quantum is admitted by its shape.
pub struct QemuHotForkConsoleRestore {
    custody: ConsoleLaunchCustody,
    saved: ConsoleOriginContinuation,
    calibration: QemuLogicalTimeCalibration,
    node: crucible::NodeId,
    boundary: Option<crate::mapped_quantum::restore::QemuLogicalTimeRestoreBoundary>,
    stopped_control_notified: bool,
    accepted_ready: Option<crucible::NodeCounter>,
    deadline: HostSupervisionAbsoluteDeadline,
    stopped_restore_ack: crate::QemuStoppedRestoreAckCapability,
}

impl std::fmt::Debug for QemuHotForkConsoleRestore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkConsoleRestore")
            .field("custody", &self.custody)
            .field("calibration", &self.calibration)
            .field("requested", &self.boundary.is_some())
            .field("accepted", &self.accepted_ready.is_some())
            .finish_non_exhaustive()
    }
}

impl QemuHotForkConsoleRestore {
    #[cfg(test)]
    pub(super) const fn retained_deadline_for_test(&self) -> HostSupervisionAbsoluteDeadline {
        self.deadline
    }

    pub(crate) fn prepare(
        parent: &ConsoleLaunchCustody,
        region: crucible_shmem::MappedSetupRegion,
        admission: &QemuHotForkConsoleAdmission,
    ) -> Result<Self, QemuNodeChannelError> {
        let custody = parent
            .rebind_hot_fork_child(region, admission.request, &admission.saved)
            .map_err(|source| console_child_error("admit child console capability", source))?;
        Ok(Self {
            custody,
            saved: admission.saved.clone(),
            calibration: admission.calibration,
            node: admission.saved.node().clone(),
            boundary: None,
            stopped_control_notified: false,
            accepted_ready: None,
            deadline: admission.deadline,
            stopped_restore_ack: admission.stopped_restore_ack.clone(),
        })
    }

    pub(crate) fn arm(&mut self) -> Result<(), QemuNodeChannelError> {
        if self.boundary.is_some() {
            return Ok(());
        }
        let region = self.custody.hot_fork_region();
        let slot = region
            .node_slot(self.custody.slot_index())
            .map_err(|source| child_error("pause child console restore", source))?;
        region
            .header()
            .request_pause([slot])
            .map_err(|source| child_error("pause child console restore", source))?;
        let publication = self
            .custody
            .arm_hot_fork_restore(&self.saved, self.calibration.logical_icount)
            .map_err(|source| console_child_error("arm child console restore", source))?;
        self.boundary = Some(
            crate::mapped_quantum::restore::QemuLogicalTimeRestoreBoundary::from_console_publication(
                publication,
                region.backing_identity(),
                self.custody.slot_index(),
            ),
        );
        Ok(())
    }

    pub(crate) fn acknowledged(&self) -> Result<bool, QemuNodeChannelError> {
        let boundary = self.boundary.ok_or_else(|| {
            QemuNodeChannelError::new("observe child console restore", "Restore is not armed")
        })?;
        let snapshot = self
            .custody
            .hot_fork_region()
            .node_slot(self.custody.slot_index())
            .map_err(|source| child_error("observe child console restore", source))?
            .try_snapshot()
            .ok_or_else(|| {
                QemuNodeChannelError::publication_unavailable("observe child console restore")
            })?;
        boundary.acknowledged(snapshot, self.calibration)
    }

    fn await_ack_notification(
        &self,
        remaining: std::time::Duration,
    ) -> Result<crucible_shmem::ControlBoundaryWaitOutcome, QemuNodeChannelError> {
        let boundary = self.boundary.ok_or_else(|| {
            QemuNodeChannelError::new("wait for child console restore", "Restore is not armed")
        })?;
        let slot = self
            .custody
            .hot_fork_region()
            .node_slot(self.custody.slot_index())
            .map_err(|source| child_error("wait for child console restore", source))?;
        // The exact producer releases coherent custody before the odd ACK. A
        // changed token with an unavailable or inconsistent full boundary is
        // a refusal, not another word on which to park without a promised wake.
        if slot.control_boundary_token() != boundary.control_request() {
            return match self.acknowledged() {
                Ok(true) => Ok(crucible_shmem::ControlBoundaryWaitOutcome::ValueChanged),
                Ok(false) => Err(QemuNodeChannelError::new(
                    "wait for child console restore",
                    "the changed control ACK lacks the original logical Restore completion",
                )),
                Err(source) => Err(source),
            };
        }
        slot.wait_control_boundary_ack(boundary.control_request(), remaining)
            .map_err(|source| child_error("wait for child console restore", source))
    }

    pub(crate) fn accept(&mut self) -> Result<(), QemuNodeChannelError> {
        if self.accepted_ready.is_some() {
            return Ok(());
        }
        let boundary = self.boundary.ok_or_else(|| {
            QemuNodeChannelError::new("accept child console restore", "Restore is not armed")
        })?;
        let ready = self
            .custody
            .accept_hot_fork_restored(boundary, self.calibration, &self.saved)
            .map_err(|source| console_child_error("accept child console restore", source))?;
        self.accepted_ready = Some(ready);
        Ok(())
    }

    /// Returns the logical node sealed into the original child Restore receipt.
    pub(crate) fn node(&self) -> &crucible::NodeId {
        &self.node
    }

    pub(crate) fn accepted_custody(&self) -> Result<ConsoleLaunchCustody, QemuNodeChannelError> {
        if self.accepted_ready.is_none() {
            return Err(QemuNodeChannelError::new(
                "attach child console custody",
                "the exact Restore prefix has not been accepted",
            ));
        }
        Ok(self.custody.clone())
    }

    pub(super) fn into_observation(
        self,
    ) -> Result<super::native_console::QemuNativeConsoleObservation, QemuNodeChannelError> {
        let ready = self.accepted_ready.ok_or_else(|| {
            QemuNodeChannelError::new("install child console observation", "Restore is unaccepted")
        })?;
        self.custody.hot_fork_region().header().clear_pause();
        Ok(
            super::native_console::QemuNativeConsoleObservation::from_restored(
                self.custody,
                self.node,
                ready,
            ),
        )
    }
}

/// Preserves coherent-read refusal only for the actual console custody error.
///
/// A retained child transaction may retry its unavailable step without issuing
/// another ceiling/body. Other console refusals and generic channel failures
/// remain fatal; this classification does not authenticate native ownership.
fn console_child_error(operation: &'static str, source: ConsoleOwnerError) -> QemuNodeChannelError {
    match source {
        ConsoleOwnerError::Unavailable => QemuNodeChannelError::publication_unavailable(operation),
        source => child_error(operation, source),
    }
}

fn child_error(operation: &'static str, source: impl std::fmt::Display) -> QemuNodeChannelError {
    QemuNodeChannelError::new(operation, source.to_string())
}

/// Borrows the original factory inputs through its stopped child transition.
pub(super) struct StoppedChildRestore<'a> {
    pub(super) request: crate::QmpHotForkRequest,
    pub(super) descriptor: &'a OwnedFd,
    pub(super) endpoint: &'a QemuHotForkPluginEndpointStageProof,
    pub(super) saved: &'a ConsoleOriginContinuation,
    pub(super) calibration: QemuLogicalTimeCalibration,
    pub(super) policy: QemuAsyncDriverPolicy,
    pub(super) stopped_restore_ack: &'a crate::QemuStoppedRestoreAckCapability,
}

/// Completes the existing child installation while its guest remains stopped.
///
/// The native runtime's Active status means that QUERY/RELEASE finished opening
/// admissions. It does not grant guest execution: native restore_pending and
/// the paused QMP state remain required through the exact Restore ACK/frontier.
pub(super) fn complete_restore(
    channels: &mut QemuNodeChannels,
    host_io_runtime: &mut dyn crate::QemuHostIoRuntime,
    process: &mut dyn QemuNodeExternalProcessControl,
    original: StoppedChildRestore<'_>,
    pending: &mut Option<QemuHotForkConsoleRestore>,
) -> Result<super::native_console::QemuNativeConsoleObservation, QemuNodeChannelError> {
    let StoppedChildRestore {
        request,
        descriptor,
        endpoint,
        saved,
        calibration,
        policy,
        stopped_restore_ack,
    } = original;
    if let Some(restore) = pending.as_ref() {
        restore
            .stopped_restore_ack
            .require_launch(stopped_restore_ack.launch_identity())
            .map_err(|source| {
                child_error("retain stopped-Restore notification capability", source)
            })?;
    }
    // An issued request keeps its first absolute deadline through retry. A
    // rejected pre-publication attempt has no outstanding native transaction.
    let deadline = if let Some(restore) = pending.as_ref() {
        restore.deadline
    } else {
        HostSupervisionAbsoluteDeadline::checked_after(policy.qmp_command_timeout).ok_or_else(
            || QemuNodeChannelError::new("restore child console", "the original timeout overflows"),
        )?
    };
    let runtime = channels
        .qmp_machine_control
        .query_hot_fork_child_runtime()?;
    let identity = endpoint.identity();
    // The strict Active response clears the workers-ready staging flag after
    // RELEASE; that flag belongs to WorkersHeld, never the released child.
    if !runtime.registered()
        || !runtime.manifest_consistent()
        || runtime.phase() != crate::QmpHotForkChildRuntimePhase::Active
        || !runtime.active()
        || runtime.failed()
        || runtime.callbacks_held()
        || !runtime.mapping_installed()
        || runtime.workers_ready()
        || runtime.parent_process_generation() != request.parent_process_generation()
        || runtime.child_process_generation() != request.child_process_generation()
        || runtime.process_generation() != request.child_process_generation()
        || runtime.template_generation() != request.template_generation()
        || runtime.private_ring_generation() != request.private_ring_generation()
        || runtime.plugin_endpoint_generation() != request.plugin_endpoint_generation()
        || runtime.plugin_barrier_generation() != request.plugin_barrier_generation()
        || runtime.control_socket_cookie() != identity.control_socket_cookie()
        || runtime.wake_eventfd_id() != identity.wake_eventfd_id()
        || runtime.worker_mask() != endpoint.worker_mask()
        || !channels
            .qmp_machine_control
            .is_paused_for_hot_fork_template()?
    {
        return Err(QemuNodeChannelError::new(
            "restore child console",
            "the actual released child runtime or paused fork basis differs",
        ));
    }

    if pending.is_none() {
        let admission = QemuHotForkConsoleAdmission {
            request,
            descriptor: descriptor
                .try_clone()
                .map_err(|source| child_error("retain child console descriptor", source))?,
            saved: saved.clone(),
            calibration,
            deadline,
            stopped_restore_ack: stopped_restore_ack.clone(),
        };
        *pending = Some(
            channels
                .shmem_hot_path
                .prepare_hot_fork_console_restore(&admission)?,
        );
    }
    let restore = pending.as_mut().ok_or_else(|| {
        QemuNodeChannelError::new("restore child console", "private Restore custody is absent")
    })?;
    if deadline.remaining().is_zero() {
        return Err(QemuNodeChannelError::new(
            "restore child console",
            "the original absolute deadline elapsed",
        ));
    }
    restore.arm()?;
    ensure_child_live(process)?;
    if !restore.stopped_control_notified {
        channels.plugin_control.signal_stopped_control()?;
        // A failed signal leaves this false. Once a wake succeeds, every
        // retained-custody continuation waits on the same public ACK edge.
        restore.stopped_control_notified = true;
    }
    await_restore_ack(restore, process)?;
    if !channels
        .qmp_machine_control
        .is_paused_for_hot_fork_template()?
    {
        return Err(QemuNodeChannelError::new(
            "accept child console restore",
            "the child guest is no longer stopped",
        ));
    }
    restore.accept()?;
    channels
        .shmem_hot_path
        .attach_hot_fork_console_restore(restore)?;
    // Both original control publishers must retain the same accepted child
    // owner before the paused child can receive a fingerprint or device probe.
    host_io_runtime
        .attach_hot_fork_console_restore(restore, saved.node())
        .map_err(|source| child_error("attach child console host-I/O custody", source))?;

    // All fallible mapped acceptance/attachment checks have completed. Moving
    // the observation cannot issue a new body, consume bytes or resume QEMU.
    let restored = pending.take().ok_or_else(|| {
        QemuNodeChannelError::new("install child console", "accepted custody disappeared")
    })?;
    restored.into_observation()
}

/// Waits only on the issued Restore's ACK and never renews its original budget.
///
/// The process loan observes the real parent's terminal status before and
/// after each bounded wait. Exit without an ACK wake is discovered at the
/// original deadline; this is not an immediate process-exit interrupt.
fn await_restore_ack(
    restore: &QemuHotForkConsoleRestore,
    process: &mut dyn QemuNodeExternalProcessControl,
) -> Result<(), QemuNodeChannelError> {
    loop {
        ensure_child_live(process)?;
        let remaining = restore.deadline.remaining();
        if remaining.is_zero() {
            return Err(QemuNodeChannelError::new(
                "restore child console",
                "the exact Restore ACK was absent at the original absolute deadline",
            ));
        }
        match restore.acknowledged() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(source) if source.is_publication_unavailable() => {}
            Err(source) => return Err(source),
        }

        // Expected-word FUTEX_WAIT closes an ACK racing this park. EINTR and
        // spurious wakes return to the same predicate and absolute deadline.
        // No second doorbell, Restore body, ceiling or authorization is issued.
        let remaining = restore.deadline.remaining();
        if remaining.is_zero() {
            continue;
        }
        restore.await_ack_notification(remaining)?;
        ensure_child_live(process)?;
    }
}

fn ensure_child_live(
    process: &mut dyn QemuNodeExternalProcessControl,
) -> Result<(), QemuNodeChannelError> {
    if process.reaped()
        || process
            .try_wait_natural_exit()
            .map_err(|source| child_error("observe child during console restore", source))?
            .is_some()
    {
        return Err(QemuNodeChannelError::new(
            "restore child console",
            "the retained child process exited before Restore acceptance",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "hot_fork_native_console/ack_wait_tests.rs"]
mod ack_wait_tests;
