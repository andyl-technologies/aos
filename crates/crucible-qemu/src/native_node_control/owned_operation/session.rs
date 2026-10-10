//! Owns the original native preparation before any Compute reservation or send.
//!
//! The unique child, accepted endpoint, initial query/ACK journal and vacant
//! command archive move together into one operation. Failed conversion retains
//! the complete session before reservation or the complete fenced operation
//! afterward. Historical initial records never issue a common prepared token.

// SPDX-License-Identifier: Apache-2.0

use std::process::Child;
use std::time::Duration;

use crucible_protocol::node_control::{
    NativeEffectCompute, NativePrefixPreparation, NativePrefixPreparationFacts,
};

use crate::native_node_control::NativeAdministrationTransport;
use crate::{QemuNodeChild, QemuShutdownTargetError};

use super::{
    Archive, ArchiveError, InitialEvidenceStore, NativeOwnedPrefixOperation,
    NativeOwnedPrefixRefusal, OriginalOperationDriver, OriginalPrefixJournal,
    OriginalPreparationDriver, OriginalPreparationProgress, TurnoverState,
};

/// Owns the original process and initial protocol journal before any Compute.
///
/// This type cannot be cloned or restored from storage. It admits conversion
/// only after the same source endpoint returned complete initial facts and the
/// consumed ACK, both durably retained. Current native roles and effect cuts
/// remain independently authenticated inside QEMU.
pub struct NativeOwnedPrefixSession {
    child: QemuNodeChild,
    preparation: OriginalPreparationDriver<NativeAdministrationTransport>,
    archive: Archive,
    refusal: Option<NativeOwnedPrefixRefusal>,
}

/// Retains every original owner when consuming a session fails.
///
/// Exactly one of the session and operation is present. Reservation failures
/// retain the operation and its initial history, while precondition failures
/// preserve the unchanged session and offered command before reservation.
pub struct NativePrefixStartFailure {
    original: NativeEffectCompute,
    session: Option<NativeOwnedPrefixSession>,
    operation: Option<NativeOwnedPrefixOperation>,
}

impl NativePrefixStartFailure {
    /// Borrows the complete command offered to the original session.
    pub fn original(&self) -> &NativeEffectCompute {
        &self.original
    }

    /// Borrows the session retained when conversion refused before reservation.
    pub fn session(&self) -> Option<&NativeOwnedPrefixSession> {
        self.session.as_ref()
    }

    /// Borrows the operation retained after attempted durable reservation.
    pub fn operation(&self) -> Option<&NativeOwnedPrefixOperation> {
        self.operation.as_ref()
    }

    /// Reaps the same child while preserving the failed owner and all journals.
    ///
    /// # Errors
    /// Retains the unique wait authority on kernel failure or deadline exhaustion.
    /// Every subsequent protocol send stays fenced after disposal starts.
    pub fn dispose(&mut self, timeout: Duration) -> Result<(), QemuShutdownTargetError> {
        if let Some(session) = &mut self.session {
            return session.dispose(timeout);
        }
        if let Some(operation) = &mut self.operation {
            return operation.dispose(timeout);
        }
        Err(QemuShutdownTargetError::new(
            "session containment",
            "missing retained owner",
        ))
    }
}

impl NativeOwnedPrefixSession {
    /// Retains the actual child and fsyncs its original query without reserving Compute.
    ///
    /// A foreign child or nonvacant archive returns an inert session retaining
    /// every supplied owner. Query exposure remains subject to actual child
    /// supervision and the preparation driver's retained refusal.
    pub fn retain(
        child: Child,
        endpoint: NativeAdministrationTransport,
        archive: Archive,
        initial: InitialEvidenceStore,
    ) -> Self {
        Self::retain_owned(QemuNodeChild::new(child), endpoint, archive, initial)
    }

    pub(super) fn retain_owned(
        child: QemuNodeChild,
        endpoint: NativeAdministrationTransport,
        archive: Archive,
        initial: InitialEvidenceStore,
    ) -> Self {
        let matches = endpoint.original_process_matches(child.process_id());
        Self {
            child,
            preparation: OriginalPreparationDriver::retain(endpoint, initial),
            archive,
            refusal: (!matches).then_some(NativeOwnedPrefixRefusal::ProcessBinding),
        }
    }

    /// Returns the unchanged original child identifier.
    pub fn process_id(&self) -> u32 {
        self.child.process_id()
    }

    /// Reports only an actual observed child reap.
    pub fn reaped(&self) -> bool {
        self.child.reaped()
    }

    /// Borrows the complete initial response after independent original matching.
    pub fn facts(&self) -> Option<&NativePrefixPreparationFacts> {
        self.preparation.facts()
    }

    /// Borrows the full independently retained preparation on the same endpoint.
    ///
    /// This immutable constructor identity is not a current Ready attestation.
    pub fn preparation(&self) -> Option<&NativePrefixPreparation> {
        self.preparation.endpoint().prefix_preparation()
    }

    /// Borrows the retained preparation or storage refusal.
    pub fn preparation_failure(&self) -> Option<&ArchiveError> {
        self.preparation.failure()
    }

    /// Borrows the first permanent process supervision refusal.
    pub fn supervision_refusal(&self) -> Option<&NativeOwnedPrefixRefusal> {
        self.refusal.as_ref()
    }

    /// Reports the command storage fence before any Compute reservation.
    pub fn archive_state(&self) -> TurnoverState {
        self.archive.state()
    }

    /// Advances only the original initial query or ACK while supervising the child.
    ///
    /// # Errors
    /// Refuses child death, permanent custody failure or nonvacant command storage.
    /// Busy leaves the original request and credits pending; no Compute is sent.
    pub fn poll(&mut self) -> Result<OriginalPreparationProgress, ArchiveError> {
        self.check_child()?;
        if self.archive.state() != TurnoverState::Vacant {
            return Err(ArchiveError::Conflict);
        }
        let progress = self.preparation.poll()?;
        self.check_child()?;
        Ok(progress)
    }

    /// Consumes the same original session into one durably reserved operation.
    ///
    /// The failure capsule is allocated before reservation. The actual child wait
    /// authority and all initial bodies move once; no process is reconstructed.
    /// An offered ACK or historical file cannot satisfy these preconditions.
    ///
    /// # Errors
    /// Returns the complete session before reservation on child, initial-journal,
    /// preparation, command or vacant-storage refusal. After reservation begins,
    /// a durability error returns the complete fenced operation instead.
    pub fn into_operation(
        self,
        original: NativeEffectCompute,
    ) -> Result<NativeOwnedPrefixOperation, Box<NativePrefixStartFailure>> {
        let mut failure = Box::new(NativePrefixStartFailure {
            original,
            session: Some(self),
            operation: None,
        });
        let Some(session) = failure.session.as_mut() else {
            return Err(failure);
        };
        if session.check_child().is_err()
            || !session.preparation.settled()
            || !session
                .preparation
                .endpoint()
                .original_process_matches(session.child.process_id())
            || session.archive.state() != TurnoverState::Vacant
        {
            return Err(failure);
        }
        let Some(preparation) = session.preparation.endpoint().prefix_preparation() else {
            return Err(failure);
        };
        if preparation.maximum_prefixes != session.archive.maximum_prefixes()
            || OriginalPrefixJournal::new(preparation, failure.original.clone()).is_err()
        {
            return Err(failure);
        }

        let Some(session) = failure.session.take() else {
            return Err(failure);
        };
        let (endpoint, evidence) = session.preparation.into_parts();
        let driver =
            OriginalOperationDriver::retain(endpoint, session.archive, failure.original.clone());
        let operation = NativeOwnedPrefixOperation::from_session(session.child, driver, evidence);
        if operation.operation_failure().is_some() {
            failure.operation = Some(operation);
            return Err(failure);
        }
        Ok(operation)
    }

    /// Force-kills and boundedly reaps the original child without discarding evidence.
    ///
    /// # Errors
    /// Preserves this session on kernel wait failure or an unreaped deadline.
    /// Later calls retry containment with the same wait authority and no sends.
    pub fn dispose(&mut self, timeout: Duration) -> Result<(), QemuShutdownTargetError> {
        self.quarantine();
        self.child.force_kill_and_reap_failed_helper(timeout)
    }

    /// Fences all protocol work while retaining every original owner and journal.
    ///
    /// It preserves an earlier refusal and sends no packet or signal.
    pub fn quarantine(&mut self) {
        if self.refusal.is_none() {
            self.refusal = Some(NativeOwnedPrefixRefusal::DisposalStarted);
        }
    }

    /// Advances actual containment without blocking the owning runtime actor.
    ///
    /// # Errors
    /// Preserves the unique Child and journals on actual kernel failure. A false
    /// result requires a later actor poll and never releases native custody.
    pub fn poll_disposal(&mut self) -> Result<bool, QemuShutdownTargetError> {
        self.quarantine();
        self.child.poll_force_kill_and_reap_failed_helper()
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
