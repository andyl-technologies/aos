//! Classifies one actual accepted placement receipt without completing its work.
//!
//! The policy State guard orders admission and completion while this loan checks
//! the same registry and actual operation allocation. The original stays live;
//! native mailbox/original/source/fault readiness remains a separate prerequisite.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};

use super::super::super::{LiveOperation, State};
use super::OperationRegistry;
use crate::paged_ram::source::SourceOperation;
use crate::ram_error::RamError;

pub(super) struct HeldWorkRecord {
    generation: u64,
    operation: Weak<dyn SourceOperation>,
}

/// Borrows the exact policy guard that orders this work's admission and completion.
pub(crate) struct CheckpointWorkAdmission<'a> {
    /// Keeps policy admission/completion ordered for the whole classifier call.
    pub(in crate::paged_ram::controller) state: &'a mut State,
    /// Pins the actual State allocation of this controller.
    pub(in crate::paged_ram::controller) state_owner: &'a Arc<Mutex<State>>,
    /// Borrows the same precharged work registry, without issuing a bank.
    pub(in crate::paged_ram::controller) registry: &'a Arc<OperationRegistry>,
    /// Names the already held policy cut, rather than granting native authority.
    pub(in crate::paged_ram::controller) generation: u64,
    // Only controller constructors under an active RELEASE or live LOCAL
    // observer select cleanup identity; this grants no operation/read authority.
    pub(in crate::paged_ram::controller) cleanup: bool,
}

/// Retains one real queued operation and its same-registry unfinished disposition.
pub(crate) struct HeldCheckpointWork {
    operation: Arc<dyn SourceOperation>,
    registry: Arc<OperationRegistry>,
    generation: u64,
    released: bool,
}

impl CheckpointWorkAdmission<'_> {
    /// Borrows only the root already installed in this exact State admission cut.
    ///
    /// # Errors
    /// Refuses an absent or foreign root. Native calls still authenticate their
    /// own current callback/thread; policy generations cannot construct a root.
    pub(crate) fn with_native_root<T>(
        &mut self,
        action: impl FnOnce(&mut crate::runtime::NativeRoot) -> Result<T, RamError>,
    ) -> Result<T, RamError> {
        let root = self
            .state
            .checkpoint
            .native_root
            .as_mut()
            .filter(|root| root.transaction() == self.generation)
            .ok_or(RamError::Invariant(
                "checkpoint admission native root absent",
            ))?;
        action(root)
    }

    /// Refuses every unfinished operation when no actual receipt loan is held.
    ///
    /// # Errors
    /// Refuses a changed policy or live/uncertain work in the same registry.
    pub(crate) fn check_settled(&self) -> Result<(), RamError> {
        self.check_policy_identity()?;
        self.registry.check_settled()
    }

    fn check_policy_identity(&self) -> Result<(), RamError> {
        if self.cleanup {
            self.state
                .check_checkpoint_cleanup_identity(self.generation)
        } else {
            self.state.check_checkpoint_policy(self.generation)
        }
    }

    /// Matches the actual controller, registry, class and unfinished token.
    pub(in crate::paged_ram::controller) fn matches(&self, operation: &LiveOperation) -> bool {
        Arc::ptr_eq(&operation.state, self.state_owner)
            && Arc::ptr_eq(&operation.operations, self.registry)
            && operation.class == 6
            && operation.tracked
            && operation.terminal.load(Ordering::Acquire) == 0
            && self.check_policy_identity().is_ok()
    }

    /// Retains the actual receipt alias before later capture predicates refuse.
    ///
    /// # Errors
    /// Refuses foreign or terminal work, busy custody or an existing loan.
    pub(in crate::paged_ram::controller) fn retain(
        &mut self,
        operation: Arc<LiveOperation>,
    ) -> Result<HeldCheckpointWork, RamError> {
        if !self.matches(&operation) {
            return Err(RamError::Invariant("checkpoint work owner does not match"));
        }
        let mut held = self
            .registry
            .held
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint work custody busy"))?;
        if held.is_some() {
            return Err(RamError::Invariant("checkpoint work loan already retained"));
        }
        let operation: Arc<dyn SourceOperation> = operation;
        *held = Some(HeldWorkRecord {
            generation: self.generation,
            operation: Arc::downgrade(&operation),
        });
        Ok(HeldCheckpointWork {
            operation,
            registry: self.registry.clone(),
            generation: self.generation,
            released: false,
        })
    }
}

impl HeldCheckpointWork {
    /// Checks this exact retained receipt, allowing no other unfinished work.
    ///
    /// # Errors
    /// Refuses another policy/registry/operation, terminal work, live unrelated
    /// work, poisoned custody or permanent disposition uncertainty. This
    /// structural predicate does not check native original deadlines or Ready.
    pub(crate) fn check(&self, admission: &CheckpointWorkAdmission<'_>) -> Result<(), RamError> {
        let held = self
            .registry
            .held
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint work custody busy"))?;
        self.check_record(admission, held.as_ref())
    }

    fn check_record(
        &self,
        admission: &CheckpointWorkAdmission<'_>,
        held: Option<&HeldWorkRecord>,
    ) -> Result<(), RamError> {
        if self.released
            || self.generation != admission.generation
            || !Arc::ptr_eq(&self.registry, admission.registry)
            || !self.operation.matches_checkpoint_work(admission)
            || held.is_none_or(|held| {
                held.generation != self.generation
                    || !Weak::ptr_eq(&held.operation, &Arc::downgrade(&self.operation))
            })
        {
            return Err(RamError::Invariant("checkpoint held work identity changed"));
        }
        // The allowance is derived from the one actual retained receipt, never
        // a caller-supplied count. State still prevents admission/completion.
        if self.registry.unfinished.load(Ordering::Acquire) != 1 {
            return Err(RamError::Invariant(
                "checkpoint unrelated work remains live",
            ));
        }
        if self.registry.uncertain.load(Ordering::Acquire) {
            return Err(RamError::Invariant("checkpoint work disposition uncertain"));
        }
        Ok(())
    }

    /// Disposes only this loan after the native owner restored its exact mailbox.
    ///
    /// # Errors
    /// Refuses changed custody or any other unfinished/uncertain work, keeping
    /// the loan held. The original operation remains unfinished and unrenewed.
    pub(crate) fn release_after_restore(
        &mut self,
        admission: &CheckpointWorkAdmission<'_>,
    ) -> Result<(), RamError> {
        let mut held = self
            .registry
            .held
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint work custody busy"))?;
        self.check_record(admission, held.as_ref())?;
        held.take();
        self.released = true;
        Ok(())
    }
}

impl Drop for HeldCheckpointWork {
    fn drop(&mut self) {
        if !self.released {
            // Losing the loan never classifies a held operation as complete.
            // Keep the named Weak record and sticky uncertainty in the actual
            // registry, even if the last original operation alias later drops.
            self.registry.uncertain.store(true, Ordering::Release);
        }
    }
}
