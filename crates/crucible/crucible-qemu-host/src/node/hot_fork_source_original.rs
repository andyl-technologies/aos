//! Lends a paused node's entered checkpoint Original to its late image helper.
//!
//! Only the actual node pairs its retained installed Source share with its
//! already entered checkpoint loan. Clones retain that operation's deadline,
//! cancellation subscriber and funding; they never enter or renew an operation.

use super::{
    CheckpointOriginalCause, CheckpointOriginalError, CheckpointOriginalLoan, QemuNode,
    QemuNodeError,
};
use crate::linux_attempt_host::{OriginalActorAccountError, SourceCleanupLender};
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};

/// Retains one actual Source's already entered hot-fork checkpoint Original.
///
/// The paused node issues this loan from its own installed process binding and
/// checkpoint owner. No public constructor accepts a guard or copied identity.
/// A helper must independently match its current Source before every birth.
#[derive(Clone, Debug)]
pub struct QemuHotForkSourceOriginal {
    lender: SourceCleanupLender,
    original: CheckpointOriginalLoan,
}

impl QemuHotForkSourceOriginal {
    /// Borrows the retained operation without issuing another guard.
    pub(crate) fn guard(&self) -> &HostOperationGuard {
        self.original.guard()
    }

    /// Checks the exact Source and the original event, deadline and policy.
    ///
    /// # Errors
    /// Refuses changed Source custody, cancellation, expiry or unavailable state.
    pub(crate) fn check(&self, receiver: &SourceCleanupLender) -> Result<(), HostSupervisionError> {
        if !self.lender.same_identity(receiver) {
            return Err(HostSupervisionError::Unavailable);
        }
        self.lender
            .controller()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        self.original.check()
    }

    /// Lends the same guard only after authenticating its current Source.
    ///
    /// # Errors
    /// Preserves Source, event, deadline and policy refusals before helper birth.
    pub(crate) fn checked_original(
        &self,
        receiver: &SourceCleanupLender,
    ) -> Result<&HostOperationGuard, crate::QemuSpawnError> {
        self.check(receiver)
            .map_err(|source| crate::QemuSpawnError::SourceAdmission {
                source: source.into(),
            })?;
        Ok(self.guard())
    }
}

impl QemuNode {
    /// Pairs this node's actual installed Source with its entered checkpoint.
    ///
    /// # Errors
    /// Refuses an absent, changed or retired Source or unavailable checkpoint loan.
    pub(crate) fn hot_fork_source_original(
        &self,
    ) -> Result<QemuHotForkSourceOriginal, QemuNodeError> {
        let lender = self
            .original_native_binding
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)
            .and_then(|binding| binding.source_helper_lender())
            .map_err(|_| QemuNodeError::CheckpointOriginal {
                source: CheckpointOriginalError::before(
                    CheckpointOriginalCause::SourceBindingUnavailable,
                ),
            })?;
        let original = self.checkpoint_original_loan()?;
        Ok(QemuHotForkSourceOriginal { lender, original })
    }
}
