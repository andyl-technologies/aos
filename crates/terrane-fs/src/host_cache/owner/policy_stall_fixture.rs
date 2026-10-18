//! Holds the actual worker's embedded-policy mutex for native read controls.
//!
//! This module exists only in explicitly requested native fixture builds. It
//! creates no native source, quota receipt, pin, validity claim or readiness.

use super::retention::{Command, NativeMetadataOwner};
use std::{io, sync::mpsc};
use tokio::sync::oneshot;

/// Keeps the actual embedded-policy mutex held until the fixture drops it.
///
/// The worker acknowledges only after locking its real policy custody. Dropping
/// this control closes the release channel, allowing that same worker to unlock.
/// Fixtures must release it before dropping the owner or submitting another
/// queued command. Reading an already-retained source needs neither operation.
pub struct NativePolicyStall {
    _release: mpsc::SyncSender<()>,
}

impl NativeMetadataOwner {
    /// Holds the real embedded-policy mutex for a native fixture's read control.
    ///
    /// This makes a stale queue-based or mutex-taking read fail the guest's
    /// deadline while a genuine retained sealed source can still read. The
    /// command performs no policy mutation or native-authority construction.
    ///
    /// # Errors
    /// Refuses a stopped/full owner queue, a poisoned policy mutex or a worker
    /// that terminates before acknowledging the actually held lock.
    pub async fn stall_policy_for_fixture(&self) -> io::Result<NativePolicyStall> {
        let (started, acknowledged) = oneshot::channel();
        let (release, released) = mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture owner stopped"))?
            .try_send(Command::HoldPolicyForFixture { started, released })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "fixture queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "fixture owner stopped")
                }
            })?;
        acknowledged
            .await
            .map_err(|_| io::Error::other("fixture worker stopped"))??;
        Ok(NativePolicyStall { _release: release })
    }
}
