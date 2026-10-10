//! Retires the actual unserved packaged owner under its external original.
//!
//! Worker completion precedes materializer shutdown so accepted checkpoint
//! messages drain through their existing receiver. This path creates no owner
//! thread or response channel. The enclosing actor keeps the entire executor
//! on every refusal, including a cause returned by an already joined thread.

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use super::*;
use crate::executor_pool::original_retirement::OriginalPoolRetirementError;
use exact_pin_materializer::original_retirement::OriginalMaterializerRetirementError;

/// Retains the genuine packaged retirement cause without a late carrier birth.
#[derive(Debug, thiserror::Error)]
pub enum OriginalPackagedRetirementError {
    /// This same owner previously refused retirement and remains contained.
    #[error("original packaged retirement is terminal and retained")]
    Terminal,
    /// The same external original refused before further retirement work.
    #[error("original packaged retirement refused: {0}")]
    Original(#[from] HostSupervisionError),
    /// A source owner needs a separately implemented physical retirement path.
    #[error("packaged source owner still requires physical retirement")]
    SourceOwner,
    /// The existing worker pool remains occupied or failed.
    #[error("original worker retirement refused: {0}")]
    Workers(#[source] OriginalPoolRetirementError),
    /// The same exact-pin materializer returned its initiating cause.
    #[error("original exact-pin retirement refused: {0}")]
    Materializer(#[source] OriginalMaterializerRetirementError),
    /// Native roster custody refused after the executor body was freed.
    #[error("original native roster retirement refused: {0}")]
    Accounts(#[from] crucible_qemu::OriginalActorAccountError),
}

impl PackagedQemuExecutor {
    /// Prepares this actual owner for physical destruction under its original.
    ///
    /// # Errors
    /// Refuses a retained hot-fork source, unfinished or failed workers, the
    /// real materializer or the saved original. Refusal leaves this body owned.
    pub(crate) fn try_retire_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), OriginalPackagedRetirementError> {
        original.wait_slice()?;
        if self.hot_fork_owner.is_some() {
            return Err(OriginalPackagedRetirementError::SourceOwner);
        }
        self.service
            .try_retire_original(original)
            .map_err(OriginalPackagedRetirementError::Workers)?;
        self.exact_pin_materializer
            .try_retire_original(original)
            .map_err(OriginalPackagedRetirementError::Materializer)?;
        original.wait_slice()?;
        Ok(())
    }
}
