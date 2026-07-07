//! Checkpoint-tagged VMState control over typed QMP commands.

use crucible::Checkpoint;

use super::{
    QmpClient, QmpCommandComplete, QmpError, QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpSnapshotTag,
    QmpTimeoutStream,
};
use crate::{QemuLoadvmCommandAuthorization, QemuNodeChannelError};

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
}

impl<S> QemuQmpVmStateControlChannel<S>
where
    S: QmpTimeoutStream,
{
    /// Builds a VMState control channel over an already-negotiated QMP client.
    #[must_use]
    pub const fn new(client: QmpClient<S>) -> Self {
        Self { client }
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
    /// The authorization token must be issued by the savevm policy for either
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
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client
            .loadvm(&tag, authorization)
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
