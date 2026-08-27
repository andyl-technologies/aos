//! Checkpoint-tagged VMState control over typed QMP commands.

use std::io::Write;
use std::os::unix::net::UnixStream;

use crucible::Checkpoint;

use super::{
    QmpClient, QmpCommandComplete, QmpError, QmpHotForkRcuInventory, QmpHotForkReadiness,
    QmpHotForkThreadInventory, QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpRunStateKind,
    QmpSnapshotTag, QmpTimeoutStream,
};
use crate::{
    QMP_DEBUG_GUEST_ACTIVATION_TOKEN, QemuLoadvmCommandAuthorization, QemuNodeChannelError,
};

/// Checkpoint-tagged VMState control surface over a typed QMP client.
///
/// This wrapper is intentionally narrower than
/// [`crate::QemuQmpMachineControlChannel`]: callers must supply the checkpoint
/// metadata they are saving or restoring, and restore requires an explicit
/// [`QemuLoadvmCommandAuthorization`] token. It therefore exposes the low-level
/// QMP VMState operations needed by a real realization executor without hiding
/// replay-oracle admission behind the generic backend restore API.
#[derive(Debug)]
pub struct QemuQmpVmStateControlChannel<S> {
    client: QmpClient<S>,
    debug_guest_activation_stream: Option<UnixStream>,
}

impl<S> QemuQmpVmStateControlChannel<S>
where
    S: QmpTimeoutStream,
{
    /// Builds a VMState control channel over an already-negotiated QMP client.
    #[must_use]
    pub const fn new(client: QmpClient<S>) -> Self {
        Self {
            client,
            debug_guest_activation_stream: None,
        }
    }

    /// Returns a channel with the pre-established guest activation stream.
    #[must_use]
    pub fn with_debug_guest_activation_stream(mut self, stream: UnixStream) -> Self {
        self.debug_guest_activation_stream = Some(stream);
        self
    }

    /// Returns a channel whose QEMU launch already has the inert endpoint.
    #[must_use]
    pub fn with_predeclared_debug_guest_endpoint(mut self) -> Self {
        self.client = self.client.with_predeclared_debug_guest_endpoint();
        self
    }

    /// Connects to an established QMP stream and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QMP connection setup or capability negotiation
    /// fails.
    pub fn connect(stream: S) -> Result<Self, QmpError> {
        QmpClient::connect(stream).map(Self::new)
    }

    /// Connects with explicit snapshot-job and stream timeout policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QMP connection setup or capability negotiation
    /// fails.
    pub fn connect_with_policies(
        stream: S,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        QmpClient::connect_with_policies(stream, job_poll_policy, io_timeout_policy).map(Self::new)
    }

    /// Returns the wrapped typed QMP client.
    #[must_use]
    pub fn into_inner(self) -> QmpClient<S> {
        self.client
    }

    /// Stops guest execution for an exact checkpoint transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot enter and confirm the
    /// paused run state.
    pub fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        let state = self.client.query_status()?;
        if !state.running && state.status == crate::QmpRunStateKind::Paused {
            return Ok(());
        }
        self.client
            .stop()
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Resumes guest execution after an exact checkpoint transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU does not acknowledge the
    /// running-state transition. The first scheduler-authorized node step is
    /// the execution proof because an idle restored simulator can park before
    /// servicing a follow-up QMP status query.
    pub fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.client
            .cont_acknowledged()
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact versioned hot-fork readiness proof bitmap.
    ///
    /// This operation is observational. It does not prepare a template or
    /// infer readiness from ordinary paused state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed readiness schema.
    pub fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<QmpHotForkReadiness, QemuNodeChannelError> {
        self.client
            .query_hot_fork_readiness()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded active-thread registry.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed inventory schema and bounds.
    pub fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<QmpHotForkThreadInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_thread_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded observational RCU inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed RCU inventory schema and bounds.
    pub fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<QmpHotForkRcuInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_rcu_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Confirms that stopped-state post-restore calibration preserved the pause.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot report its state or is
    /// not in the exact paused state required after calibration.
    pub(crate) fn confirm_restore_boundary_pause(&mut self) -> Result<(), QemuNodeChannelError> {
        let state = self.client.query_status()?;
        if !state.running && state.status == QmpRunStateKind::Paused {
            return Ok(());
        }
        Err(QmpError::UnexpectedRunState {
            command: super::QmpCommandKind::QueryStatus,
            status: state.status,
            running: state.running,
        }
        .into())
    }

    /// Acknowledges one authenticated terminal lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU does not acknowledge the
    /// terminal completion command before beginning process shutdown.
    pub fn complete_terminal_lifecycle_exit(
        &mut self,
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .complete_terminal_lifecycle_exit(action, evidence, process_generation)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Sends the fixed activation token to the dormant debug guest bootstrap.
    /// The channel retains the socket so QEMU cannot discard queued bytes while
    /// the scheduler still has the guest paused.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when endpoint preparation fails or the
    /// activation stream cannot deliver the fixed token.
    pub fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        self.client
            .confirm_predeclared_debug_guest_endpoint()
            .map_err(QemuNodeChannelError::from)?;
        let activation = self.debug_guest_activation_stream.as_mut().ok_or_else(|| {
            QemuNodeChannelError::new(
                "activate debug guest",
                "fork-time guest activation stream is not configured",
            )
        })?;
        activation
            .write_all(QMP_DEBUG_GUEST_ACTIVATION_TOKEN.as_bytes())
            .map_err(|error| {
                QemuNodeChannelError::new("write debug guest activation token", error.to_string())
            })?;
        Ok(())
    }

    /// Saves the QEMU VMState under a tag derived from `checkpoint`.
    ///
    /// This operation persists only the QEMU VMState half. The caller remains
    /// responsible for storing the Crucible checkpoint metadata and node blobs.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot save the checkpoint's
    /// VMState snapshot.
    pub fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client.savevm(&tag).map_err(QemuNodeChannelError::from)
    }

    /// Restores the QEMU VMState tagged by `checkpoint`.
    ///
    /// The authorization token must be issued by the exact snapshot policy for either
    /// replay-oracle probing or admitted runtime realization.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot load the checkpoint's
    /// VMState snapshot.
    pub fn restore_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        if authorization.purpose() != crate::QemuLoadvmCommandPurpose::ReplayOracleProbe {
            return Err(QemuNodeChannelError::new(
                "qmp",
                "public VMState restore only admits replay-oracle probes",
            ));
        }
        self.restore_checkpoint_vmstate_authorized(checkpoint)
    }

    pub(crate) fn restore_checkpoint_vmstate_authorized(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client
            .loadvm_authorized(&tag)
            .map_err(QemuNodeChannelError::from)
    }

    /// Deletes the QEMU VMState artifact tagged by `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot complete deletion.
    pub fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client
            .delete_snapshot(&tag)
            .map_err(QemuNodeChannelError::from)
    }

    /// Requests graceful QEMU termination through QMP.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot send the quit command.
    pub fn quit(&mut self) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        self.client.quit().map_err(QemuNodeChannelError::from)
    }
}
