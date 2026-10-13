//! Retains policy admission through an independently owned checkpoint cut.
//!
//! This fixed state closes admission, not the pager's settlement proof. The
//! checkpoint callback must authenticate the native-held original transaction
//! before entry, retain pending fault/mailbox/source owners, and prove final
//! disposition before release. A generation only names that retained owner.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

pub(super) mod work;

#[derive(Clone, Copy, PartialEq, Eq)]
struct PolicyFence {
    requested_revision: u64,
    applied_revision: u64,
    reservation_revision: u64,
    policy: RamControlPolicy,
    resources: RamControlResources,
}

#[derive(Clone, Copy)]
struct HeldPolicy {
    generation: u64,
    fence: PolicyFence,
}

/// Keeps the policy hold in the actual controller state without a second owner.
#[derive(Default)]
pub(super) struct CheckpointAdmission {
    issued_generation: u64,
    held: Option<HeldPolicy>,
    native_root: Option<crate::runtime::NativeRoot>,
    service: Option<super::super::engine::RetainedCheckpointService>,
    retired_native_transaction: Option<u64>,
}

impl CheckpointAdmission {
    pub(super) fn is_held(&self) -> bool {
        self.held.is_some() || self.native_root.is_some()
    }
}

impl State {
    /// Rechecks the retained root from an ordinary producer's actual State lock.
    ///
    /// Failures keep admission closed. This path issues no new original, read
    /// permission or native cleanup; it follows only the physical owner's journal.
    pub(super) fn checkpoint_producer_held(
        &mut self,
        state_owner: &Arc<Mutex<State>>,
        registry: &Arc<work::OperationRegistry>,
    ) -> bool {
        if self.checkpoint.native_root.is_some() {
            let _retained_refusal = self.dispose_checkpoint_root(state_owner, registry);
        }
        self.checkpoint.is_held()
    }

    fn dispose_checkpoint_root(
        &mut self,
        state_owner: &Arc<Mutex<State>>,
        registry: &Arc<work::OperationRegistry>,
    ) -> Result<(), RamError> {
        let mut root = self
            .checkpoint
            .native_root
            .take()
            .ok_or(RamError::Invariant("checkpoint native root absent"))?;
        let result = (|| {
            let transaction = root.transaction();
            let owner = self
                .owner
                .as_ref()
                .cloned()
                .ok_or(RamError::Invariant("checkpoint paging owner absent"))?;
            let stage = if root.is_acknowledged() {
                crate::runtime::RootStage::Retired
            } else {
                root.observe()?
            };
            if stage == crate::runtime::RootStage::LocalDisposition {
                let stage = root.retire_local(|disposition| {
                    let admission = work::CheckpointWorkAdmission {
                        state: self,
                        state_owner,
                        registry,
                        generation: transaction,
                        cleanup: true,
                    };
                    owner.dispose_checkpoint_native_work(&admission, disposition)?;
                    admission
                        .state
                        .checkpoint
                        .service
                        .as_mut()
                        .ok_or(RamError::Invariant("checkpoint retained service absent"))?
                        .dispose_local(disposition)
                })?;
                if stage != crate::runtime::RootStage::Retired {
                    return Ok(false);
                }
            } else if stage != crate::runtime::RootStage::Retired {
                return Ok(false);
            }
            // The genuine native publisher must complete physical cleanup
            // before this branch can acknowledge the retained root.
            owner.finish_checkpoint_native(transaction, || {
                root.acknowledge_retired()?;
                self.checkpoint
                    .service
                    .as_mut()
                    .ok_or(RamError::Invariant("checkpoint retained service absent"))?
                    .release_worker_after_retirement(&root)
            })?;
            // Acknowledgment followed by end(0) is the last native pointer use.
            // State remains locked while the final local keeper/gate is removed.
            self.checkpoint.service.take();
            self.checkpoint.held = None;
            self.checkpoint.retired_native_transaction = Some(transaction);
            Ok(true)
        })();
        if !matches!(result, Ok(true)) {
            self.checkpoint.native_root = Some(root);
        }
        result.map(|_| ())
    }

    fn checkpoint_policy_fence(&self) -> Result<PolicyFence, RamError> {
        if self.failed
            || self.outer_expired
            || self.fork_preparing
            || self.policy_applying
            || self.child_bootstrap
            || self.requested_revision == 0
            || self.requested_revision != self.applied_revision
            || self.owner.is_none()
            || self
                .policy
                .is_some_and(|policy| self.budgets != policy.budgets)
        {
            return Err(RamError::Invariant("checkpoint policy cut unavailable"));
        }
        Ok(PolicyFence {
            requested_revision: self.requested_revision,
            applied_revision: self.applied_revision,
            reservation_revision: self.reservation_revision,
            resources: self.resources,
            policy: self
                .policy
                .ok_or("checkpoint policy identity unavailable")?,
        })
    }

    /// Closes the actual policy admission gate under the already held state lock.
    ///
    /// The matched native receiver must first authenticate its retained original;
    /// this generation names that owner and cannot itself issue capture authority.
    ///
    /// # Errors
    /// Refuses an unsettled policy, stale generation or another retained hold.
    pub(super) fn hold_checkpoint_policy(&mut self, generation: u64) -> Result<(), RamError> {
        let fence = self.checkpoint_policy_fence()?;
        if let Some(held) = self.checkpoint.held {
            if held.generation == generation && held.fence == fence {
                return Ok(());
            }
            return Err(RamError::Invariant(
                "checkpoint policy hold already retained",
            ));
        }
        if generation == 0 || generation <= self.checkpoint.issued_generation {
            return Err(RamError::Invariant("checkpoint policy generation is stale"));
        }

        self.checkpoint.issued_generation = generation;
        self.checkpoint.held = Some(HeldPolicy { generation, fence });
        Ok(())
    }

    /// Checks the exact tuple retained when policy admission was closed.
    ///
    /// # Errors
    /// Refuses another generation, terminal state or changed policy identity.
    pub(super) fn check_checkpoint_policy(&self, generation: u64) -> Result<(), RamError> {
        let held = self
            .checkpoint
            .held
            .filter(|held| held.generation == generation)
            .ok_or("checkpoint policy hold does not match")?;
        if held.fence != self.checkpoint_policy_fence()? {
            return Err(RamError::Invariant("checkpoint held policy changed"));
        }
        Ok(())
    }

    /// Checks retained cleanup identity without reviving a failed operation.
    ///
    /// # Errors
    /// Refuses changed policy/resource ownership. Terminal timing remains terminal;
    /// the authentic native RELEASE or local observer supplies cleanup authority.
    fn check_checkpoint_cleanup_identity(&self, generation: u64) -> Result<(), RamError> {
        let held = self
            .checkpoint
            .held
            .filter(|held| held.generation == generation)
            .ok_or(RamError::Invariant(
                "checkpoint cleanup policy identity absent",
            ))?;
        let current = PolicyFence {
            requested_revision: self.requested_revision,
            applied_revision: self.applied_revision,
            reservation_revision: self.reservation_revision,
            policy: self
                .policy
                .ok_or(RamError::Invariant("checkpoint cleanup policy absent"))?,
            resources: self.resources,
        };
        if held.fence != current {
            return Err(RamError::Invariant(
                "checkpoint cleanup policy identity changed",
            ));
        }
        Ok(())
    }

    /// Reopens admission after the matched native disposition frees its loans.
    ///
    /// Fault, mailbox, source/version and immutable-reader disposition must precede
    /// this call. A failed check retains the same gate; there is no Drop reopening.
    ///
    /// # Errors
    /// Refuses an unmatched generation or a changed or terminal held policy.
    pub(super) fn release_checkpoint_policy(&mut self, generation: u64) -> Result<(), RamError> {
        self.check_checkpoint_policy(generation)?;
        self.checkpoint.held = None;
        Ok(())
    }
}

impl LivePagerController {
    // Native callbacks use try-locks and borrowed supervision diagnostics. The
    // later original transaction is a separate required check, not issued here.
    fn checkpoint_state(&self) -> Result<std::sync::MutexGuard<'_, State>, RamError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| "checkpoint policy ownership busy")?;
        if self.canceled.load(Ordering::Acquire) {
            return Err(RamError::Invariant("checkpoint controller canceled"));
        }
        if state
            .outer
            .is_some_and(|cap| outer_remaining_for::<true>(cap).is_err())
        {
            state.outer_expired = true;
        }
        Ok(state)
    }

    /// Closes the same policy gate without waiting behind its actual owner.
    ///
    /// # Errors
    /// Refuses contention, cancellation, expiration or an incompatible policy cut.
    pub(super) fn prepare_checkpoint_policy(&self, generation: u64) -> Result<(), RamError> {
        self.checkpoint_state()?.hold_checkpoint_policy(generation)
    }

    /// Rechecks the retained cut without waiting or renewing its outer original.
    ///
    /// # Errors
    /// Refuses contention, cancellation, expiration or changed held identity.
    pub(super) fn check_checkpoint_policy(&self, generation: u64) -> Result<(), RamError> {
        self.checkpoint_state()?.check_checkpoint_policy(generation)
    }

    /// Borrows the actual policy guard for a same-registry queued-work disposition.
    ///
    /// # Errors
    /// Refuses a changed or busy policy cut and propagates the actual custody
    /// refusal. The closure cannot renew the original or issue native authority.
    pub(crate) fn with_checkpoint_work_admission<T>(
        &self,
        generation: u64,
        action: impl FnOnce(&mut work::CheckpointWorkAdmission<'_>) -> Result<T, RamError>,
    ) -> Result<T, RamError> {
        let mut state = self.checkpoint_state()?;
        state.check_checkpoint_policy(generation)?;
        let mut admission = work::CheckpointWorkAdmission {
            state: &mut state,
            state_owner: &self.state,
            registry: &self.operations,
            generation,
            cleanup: false,
        };
        action(&mut admission)
    }

    /// Borrows retained identity for a genuine active native RELEASE.
    ///
    /// # Errors
    /// Refuses contention or changed ownership. Native restore independently
    /// authenticates its active action/root even when the original has failed.
    fn with_checkpoint_cleanup_admission<T>(
        &self,
        generation: u64,
        action: impl FnOnce(&mut work::CheckpointWorkAdmission<'_>) -> Result<T, RamError>,
    ) -> Result<T, RamError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint cleanup State busy"))?;
        state.check_checkpoint_cleanup_identity(generation)?;
        let mut admission = work::CheckpointWorkAdmission {
            state: &mut state,
            state_owner: &self.state,
            registry: &self.operations,
            generation,
            cleanup: true,
        };
        action(&mut admission)
    }

    /// Classifies prior work without treating released body capacity as settlement.
    ///
    /// # Errors
    /// Refuses a changed held policy, live work or any abandoned admitted work.
    /// This does not prove fault ACK, native mailbox/writer or source-page fences.
    pub(super) fn check_checkpoint_prior_work(&self, generation: u64) -> Result<(), RamError> {
        self.with_checkpoint_work_admission(generation, |admission| {
            let owner = admission
                .state
                .owner
                .as_ref()
                .cloned()
                .ok_or(RamError::Invariant("checkpoint paging owner absent"))?;
            owner.check_checkpoint_work(admission, generation)
        })
    }

    /// Disposes the gate after independently established native final acceptance.
    ///
    /// # Errors
    /// Refuses contention, cancellation, expiration or changed held identity.
    pub(super) fn release_checkpoint_policy(&self, generation: u64) -> Result<(), RamError> {
        self.with_checkpoint_work_admission(generation, |admission| {
            let owner = admission
                .state
                .owner
                .as_ref()
                .cloned()
                .ok_or(RamError::Invariant("checkpoint paging owner absent"))?;
            owner.release_checkpoint_work(admission, generation)?;
            admission.state.release_checkpoint_policy(generation)
        })
    }
}

/// Retains the actual controller, paging owner and service before capture effects.
pub(crate) struct CheckpointPagerOwner {
    controller: Arc<LivePagerController>,
    owner: Arc<PausedPagingOwner>,
    service: Option<super::super::engine::RetainedCheckpointService>,
    transaction: u64,
}

impl CheckpointPagerOwner {
    /// Matches the actual held allocation for identity-only creating-Main cleanup.
    ///
    /// # Errors
    /// Refuses another State owner or returned Root. Existing source failure or
    /// an expired Original does not revoke physical claim-return identity.
    pub(crate) fn check_held_cleanup_identity(&self) -> Result<(), RamError> {
        let state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint cleanup State busy"))?;
        if self.service.is_some()
            || !state
                .owner
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
            || state
                .checkpoint
                .native_root
                .as_ref()
                .is_none_or(|root| root.transaction() != self.transaction || root.is_acknowledged())
            || state.checkpoint.service.is_none()
        {
            return Err(RamError::Invariant("checkpoint cleanup allocation changed"));
        }
        Ok(())
    }

    /// Retains existing page/source allocations for a genuine native read loan.
    ///
    /// # Errors
    /// Refuses a replaced State owner, a missing native root, or unsettled actual
    /// page/fault custody. The caller must authenticate its nominal read loan
    /// before entry and release Slot/State guards before invoking native or I/O.
    pub(crate) fn retain_held_read(
        &self,
    ) -> Result<super::super::engine::HeldCheckpointRead, RamError> {
        let state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint held reader State busy"))?;
        if self.service.is_some()
            || !state
                .owner
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
            || state
                .checkpoint
                .native_root
                .as_ref()
                .is_none_or(|root| root.transaction() != self.transaction || root.is_acknowledged())
        {
            return Err(RamError::Invariant("checkpoint held reader owner changed"));
        }
        state
            .checkpoint
            .service
            .as_ref()
            .ok_or(RamError::Invariant("checkpoint held reader service absent"))?
            .retain_read(self.transaction)
    }

    /// Rechecks the actual retained allocation before a new native operation.
    ///
    /// # Errors
    /// Refuses another State owner, a replaced installed service or contention.
    pub(crate) fn check_retained(&self) -> Result<(), RamError> {
        let state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint retained State busy"))?;
        if !state
            .owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
        {
            return Err(RamError::Invariant(
                "checkpoint retained State owner changed",
            ));
        }
        if let Some(service) = self.service.as_ref() {
            if state.checkpoint.is_held() || state.checkpoint.service.is_some() {
                return Err(RamError::Invariant(
                    "unprepared checkpoint owner has another cut",
                ));
            }
            service.check_retained()
        } else {
            if state
                .checkpoint
                .native_root
                .as_ref()
                .is_none_or(|root| root.transaction() != self.transaction)
            {
                return Err(RamError::Invariant(
                    "checkpoint retained native root changed",
                ));
            }
            state
                .checkpoint
                .service
                .as_ref()
                .ok_or(RamError::Invariant("checkpoint retained service absent"))?
                .check_retained()
        }
    }

    /// Performs the local retirement tail on the genuine creating-thread callback.
    ///
    /// # Errors
    /// Preserves native observation, local disposition and keeper failures. The
    /// caller retains its provider lease until the same State journal is final.
    pub(crate) fn finalize_retirement(&self) -> Result<bool, RamError> {
        let mut state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint final State busy"))?;
        if self.service.is_some()
            || !state
                .owner
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
        {
            return Err(RamError::Invariant("checkpoint final State owner changed"));
        }
        if let Some(root) = state.checkpoint.native_root.as_ref() {
            if root.transaction() != self.transaction {
                return Err(RamError::Invariant("checkpoint final root changed"));
            }
            state.dispose_checkpoint_root(&self.controller.state, &self.controller.operations)?;
        }
        Ok(
            state.checkpoint.retired_native_transaction == Some(self.transaction)
                && !state.checkpoint.is_held()
                && state.checkpoint.service.is_none(),
        )
    }

    /// Checks genuine unprepared allocation return without disposing any root.
    ///
    /// # Errors
    /// Refuses a prepared owner, any local cut or changed State identity. Native
    /// must separately invoke provider end under its authentic no-root journal.
    pub(crate) fn unprepared_returnable(&self) -> Result<bool, RamError> {
        let state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint unprepared State busy"))?;
        Ok(self.service.is_some()
            && state
                .owner
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
            && !state.checkpoint.is_held()
            && state.checkpoint.service.is_none())
    }

    /// Observes completed retirement from the same controller's terminal journal.
    ///
    /// # Errors
    /// Refuses State contention. Native callback return and root return do not
    /// populate this journal; acknowledgment, observer return and the actual
    /// worker/queue cleanup must have succeeded under this same State lock.
    pub(crate) fn retirement_completed(&self) -> Result<bool, RamError> {
        let state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint retirement State busy"))?;
        let same_owner = state
            .owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner));
        Ok(same_owner
            && self.service.is_none()
            && state.checkpoint.retired_native_transaction == Some(self.transaction)
            && !state.checkpoint.is_held()
            && state.checkpoint.service.is_none())
    }

    /// Installs the exact issued root before fallible policy or worker cuts.
    ///
    /// # Errors
    /// Refuses busy State or another native root while leaving Slot custody intact.
    pub(crate) fn install_native_root(
        &mut self,
        root: &mut Option<crate::runtime::NativeRoot>,
    ) -> Result<(), RamError> {
        let mut state = self
            .controller
            .state
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint root State busy"))?;
        if state.checkpoint.native_root.is_some() {
            return Err(RamError::Invariant("checkpoint root already installed"));
        }
        if root
            .as_ref()
            .is_none_or(|root| root.transaction() != self.transaction)
        {
            return Err(RamError::Invariant("checkpoint root transaction changed"));
        }
        state.checkpoint.native_root = root.take();
        state.checkpoint.service = self.service.take();
        Ok(())
    }

    /// Returns the synchronous callback loan while retaining policy admission.
    ///
    /// # Errors
    /// Refuses busy or foreign ownership and preserves the native return status.
    /// Local return never publishes final native retirement or reopens producers.
    pub(crate) fn return_native_callback(&self) -> Result<(), RamError> {
        let restored =
            self.controller
                .with_checkpoint_cleanup_admission(self.transaction, |admission| {
                    self.owner
                        .restore_checkpoint_native(admission, self.transaction)
                });
        let returned = (|| {
            let state = self
                .controller
                .state
                .try_lock()
                .map_err(|_| RamError::Invariant("checkpoint root State busy"))?;
            let root = state
                .checkpoint
                .native_root
                .as_ref()
                .filter(|root| root.transaction() == self.transaction)
                .ok_or(RamError::Invariant("checkpoint native root absent"))?;
            root.return_from_callback()
        })();
        // Restoration can physically succeed before its saved original postcut
        // refuses. The actual native return journal decides whether returning the
        // same callback loan is allowed; retain restoration as the first cause.
        restored.and(returned)
    }

    /// Requests policy, queue and worker holds under the same retained owners.
    ///
    /// # Errors
    /// Refuses changed policy, custody contention or the actual pause refusal.
    /// A successful request does not prove native detach or whole page fencing.
    pub(crate) fn request(&mut self) -> Result<(), RamError> {
        self.controller
            .prepare_checkpoint_policy(self.transaction)?;
        self.controller
            .with_checkpoint_work_admission(self.transaction, |admission| {
                self.owner
                    .request_checkpoint_work(admission, self.transaction)?;
                self.owner
                    .detach_checkpoint_native(admission, self.transaction)
            })?;
        let mut state = self.controller.checkpoint_state()?;
        state
            .checkpoint
            .service
            .as_mut()
            .ok_or(RamError::Invariant("checkpoint retained service absent"))?
            .request_pause(self.transaction)
    }

    /// Rechecks the same held policy and worker without issuing native authority.
    ///
    /// # Errors
    /// Refuses a changed policy or service. An unacknowledged worker is pending.
    pub(crate) fn worker_acknowledged(&self) -> Result<bool, RamError> {
        self.controller
            .with_checkpoint_work_admission(self.transaction, |admission| {
                admission.with_native_root(|root| root.check_active())?;
                self.owner
                    .check_checkpoint_work(admission, self.transaction)
            })?;
        let mut state = self.controller.checkpoint_state()?;
        let CheckpointAdmission {
            native_root,
            service,
            ..
        } = &mut state.checkpoint;
        let root = native_root
            .as_ref()
            .ok_or(RamError::Invariant("checkpoint native root absent"))?;
        let service = service
            .as_mut()
            .ok_or(RamError::Invariant("checkpoint retained service absent"))?;
        if !service.pause_acknowledged(self.transaction)? {
            Ok(false)
        } else {
            service.hold_pages(root).map(|()| true)
        }
    }
}

/// Retains installed owners before a callback makes any fallible capture request.
///
/// # Errors
/// Refuses missing or busy controller/service ownership and invalid transaction identity.
/// The caller must independently authenticate its active native invocation first.
pub(crate) fn retain_pager_owner(transaction: u64) -> Result<CheckpointPagerOwner, RamError> {
    if transaction == 0 {
        return Err(RamError::Invariant("checkpoint transaction absent"));
    }
    let controller = CONTROLLER
        .try_lock()
        .map_err(|_| RamError::Invariant("checkpoint controller publication busy"))?
        .as_ref()
        .cloned()
        .ok_or(RamError::Invariant("checkpoint controller absent"))?;
    let owner = controller
        .checkpoint_state()?
        .owner
        .as_ref()
        .cloned()
        .ok_or(RamError::Invariant("checkpoint paging owner absent"))?;
    let service = super::super::engine::RetainedCheckpointService::retain(owner.clone())?;
    Ok(CheckpointPagerOwner {
        controller,
        owner,
        service: Some(service),
        transaction,
    })
}

#[cfg(test)]
mod retirement_tests;
