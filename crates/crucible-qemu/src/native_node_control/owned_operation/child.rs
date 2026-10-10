//! Retains the original native child with its endpoint, command and durable journal.
//!
//! Kernel exit observations fence all later command exposure. Explicit disposal
//! keeps the same child wait authority and journal across a bounded reap failure.
//! Reaping supplies containment only; it never changes uncertain guest effects
//! into NoEffects, confirms native retirement or admits a common prepared owner.

// SPDX-License-Identifier: Apache-2.0

use std::process::{Child, ExitStatus};
use std::time::Duration;

use crucible_protocol::node_control::NativeEffectCompute;

use crate::native_node_control::NativeAdministrationTransport;
use crate::{QemuNodeChild, QemuShutdownTargetError};

use super::{
    Archive, ArchiveError, OriginalInitialEvidence, OriginalOperationDriver,
    OriginalOperationProgress, OriginalPrefixJournal, TurnoverState,
};

/// Retains a permanent supervision refusal alongside the original operation.
#[derive(Debug)]
pub enum NativeOwnedPrefixRefusal {
    /// Refuses a child different from the endpoint's original accepted process.
    ProcessBinding,
    /// Retains the actual natural child status without inferring guest effects.
    ChildExited(ExitStatus),
    /// Retains a kernel supervision error with the unique child wait authority.
    Supervision(QemuShutdownTargetError),
    /// Fences further sends once explicit containment starts, even if reap fails.
    DisposalStarted,
}

/// Owns one live native child and the complete original prefix-operation custody.
///
/// The endpoint must already retain the original process-bound administration
/// facts. Those historical facts correlate the child; native dispatch still
/// authenticates its own current roles, epoch and cut. No constructor here issues
/// a `PreparedOwner` or releases a native slot.
pub struct NativeOwnedPrefixOperation {
    child: QemuNodeChild,
    operation: OriginalOperationDriver<NativeAdministrationTransport>,
    refusal: Option<NativeOwnedPrefixRefusal>,
    initial: Option<OriginalInitialEvidence>,
}

impl NativeOwnedPrefixOperation {
    /// Retains the actual spawned child and durably reserves a fresh original command.
    ///
    /// A binding or archive refusal keeps every supplied owner in this value and
    /// prevents socket exposure. The caller must retain it until explicit bounded
    /// disposal observes a reap; dropping is only the existing child fallback.
    pub fn retain(
        child: Child,
        endpoint: NativeAdministrationTransport,
        archive: Archive,
        original: NativeEffectCompute,
    ) -> Self {
        let matches = endpoint.original_process_matches(child.id());
        Self {
            child: QemuNodeChild::new(child),
            operation: OriginalOperationDriver::retain(endpoint, archive, original),
            refusal: (!matches).then_some(NativeOwnedPrefixRefusal::ProcessBinding),
            initial: None,
        }
    }

    pub(super) fn from_session(
        child: QemuNodeChild,
        operation: OriginalOperationDriver<NativeAdministrationTransport>,
        initial: OriginalInitialEvidence,
    ) -> Self {
        Self {
            child,
            operation,
            refusal: None,
            initial: Some(initial),
        }
    }

    /// Borrows all initial session bodies retained before this command was reserved.
    pub fn initial_evidence(&self) -> Option<&OriginalInitialEvidence> {
        self.initial.as_ref()
    }

    /// Returns the actual original child identifier.
    pub fn process_id(&self) -> u32 {
        self.child.process_id()
    }

    /// Reports only an actual observed child reap.
    pub fn reaped(&self) -> bool {
        self.child.reaped()
    }

    /// Borrows the original command even after supervision or archive failure.
    pub fn original(&self) -> &NativeEffectCompute {
        self.operation.original()
    }

    /// Borrows retained prefix history without returning native-private handles.
    pub fn journal(&self) -> Option<&OriginalPrefixJournal> {
        self.operation.journal()
    }

    /// Reports the durable storage fence without confirming native retirement.
    pub fn archive_state(&self) -> TurnoverState {
        self.operation.archive_state()
    }

    /// Borrows the first permanent transport or archival refusal.
    pub fn operation_failure(&self) -> Option<&ArchiveError> {
        self.operation.failure()
    }

    /// Borrows the first permanent child supervision or containment refusal.
    pub fn supervision_refusal(&self) -> Option<&NativeOwnedPrefixRefusal> {
        self.refusal.as_ref()
    }

    /// Advances the same original operation while supervising its actual child.
    ///
    /// # Errors
    /// Refuses permanent custody failure or actual child death. Kernel status and
    /// transport failure remain separately retained; no later poll sends a frame.
    pub fn poll(&mut self) -> Result<OriginalOperationProgress, ArchiveError> {
        self.check_child()?;
        let progress = self.operation.poll()?;
        self.check_child()?;
        Ok(progress)
    }

    /// Requests a new source-selected prefix after the actual consumed original ACK.
    ///
    /// # Errors
    /// Refuses child/custody failure, an outstanding original request or unchanged
    /// native allowance exhaustion. It grants no extra instruction or callback.
    pub fn request_continuation(&mut self) -> Result<(), ArchiveError> {
        self.check_child()?;
        self.operation.request_continuation()
    }

    /// Requests byte-equal recovery of the same outstanding original frame.
    ///
    /// # Errors
    /// Refuses child/custody failure or an absent original pending request. This
    /// recovers history without granting another prefix or restoring an epoch.
    pub fn request_original_again(&mut self) -> Result<(), ArchiveError> {
        self.check_child()?;
        self.operation.request_original_again()
    }

    /// Force-kills and boundedly reaps the same child while retaining all evidence.
    ///
    /// # Errors
    /// Preserves this owner on kernel wait failure or an unreaped child after the
    /// supplied deadline. A later call retries containment with the same wait
    /// authority; all operation sends remain fenced after disposal starts.
    pub fn dispose(&mut self, timeout: Duration) -> Result<(), QemuShutdownTargetError> {
        if self.refusal.is_none() {
            self.refusal = Some(NativeOwnedPrefixRefusal::DisposalStarted);
        }
        self.child.force_kill_and_reap_failed_helper(timeout)
    }

    fn check_child(&mut self) -> Result<(), ArchiveError> {
        if self.refusal.is_some() {
            return Err(ArchiveError::Failed);
        }
        match self.child.try_wait_natural_exit() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
                self.refusal = Some(NativeOwnedPrefixRefusal::ChildExited(status));
                Err(ArchiveError::Failed)
            }
            Err(error) => {
                self.refusal = Some(NativeOwnedPrefixRefusal::Supervision(error));
                Err(ArchiveError::Failed)
            }
        }
    }
}
