//! Observes current Running custody through the original physical command queue.
//!
//! A successful check is a point-in-time observation, never a replacement for
//! native readiness, a content grant, fresh quota inspection or a publisher RPC.

use super::{
    NativeMetadataOwner,
    consumer::state,
    retention::{Command, NativeOwnerExecutor},
};
use std::{io, sync::mpsc};
use tokio::sync::oneshot;

impl NativeMetadataOwner {
    /// Checks the original worker's acknowledged Running custody.
    ///
    /// The serialized check verifies the retained native roots, synchronized
    /// snapshot, live publisher context and original bootstrap funding. It does
    /// not create readiness, inspect current kernel quota usage or contact the
    /// publisher. Normal due maintenance may run before this queue turn; the
    /// check itself changes no policy. Callers separately bound their wait;
    /// cancellation leaves queued work with its original owner.
    ///
    /// # Errors
    /// Refuses a full or stopped queue, missing or uncertain Resume, stale roots
    /// or policy provenance, lost funding, faulted custody and a changed publisher
    /// context. A prior successful check does not authorize later operations.
    pub async fn check_running(&self) -> io::Result<()> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("native owner stopped"))?
            .try_send(Command::CheckRunning { response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "native owner queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "native owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("native owner stopped before Running check"))?
    }
}

/// Checks current Running custody on its retained physical worker.
///
/// # Errors
/// Refuses an unacknowledged or changed publisher context, faulted native custody,
/// invalid snapshot provenance or missing original bootstrap funding.
pub(super) fn check(executor: &NativeOwnerExecutor) -> io::Result<()> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    {
        let custody = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("native Running custody poisoned"))?;
        state::check_ready(executor, &custody)?;
        state::check_bootstrap(&custody, &running)?;
    }
    running.check_current().map_err(io::Error::other)
}
