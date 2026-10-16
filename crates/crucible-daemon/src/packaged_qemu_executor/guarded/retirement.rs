//! Terminal retirement of the actual standalone guarded Main owner.
//!
//! Requests and sessions retain the same inner owner. Clone destruction never
//! closes Main; only explicit exclusive retirement or the final standalone
//! facade enters the original actor's terminal route. Failure keeps every field
//! and charge, and final-owner uncertainty retains that complete same Arc.

use super::*;
use crucible_api::host_operational::HostOperationalError;
use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Tracks real facade publication and release, without granting native authority.
pub(crate) struct GuardedFacadeRetirement {
    records: AtomicUsize,
    quarantined: AtomicBool,
    #[cfg(test)]
    release_barrier: Option<Arc<std::sync::Barrier>>,
}

impl GuardedFacadeRetirement {
    pub(super) const fn new() -> Self {
        Self {
            records: AtomicUsize::new(1),
            quarantined: AtomicBool::new(false),
            #[cfg(test)]
            release_barrier: None,
        }
    }

    fn publish_clone(&self) -> bool {
        !self.is_quarantined()
            && self
                .records
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |records| {
                    records.checked_add(1).filter(|_| records != 0)
                })
                .is_ok()
    }

    fn release(&self) -> Result<bool, ()> {
        if self.is_quarantined() {
            return Err(());
        }
        self.records
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |records| {
                records.checked_sub(1)
            })
            .map(|records| records == 1)
            .map_err(|_| ())
    }

    pub(crate) fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::Acquire)
    }
}

fn retain_same_uncertain_owner(inner: &Arc<GuardedOwnerInner>) {
    if !inner.facades.quarantined.swap(true, Ordering::AcqRel) {
        // This is another reference to the existing paid allocation. One
        // retained header keeps the entire same body and original custody.
        std::mem::forget(Arc::clone(inner));
    }
}

impl Clone for GuardedCampaignOwner {
    fn clone(&self) -> Self {
        let inner = Arc::clone(&self.inner);
        let lifecycle_record = self.lifecycle_record && inner.facades.publish_clone();
        if !lifecycle_record {
            // Uncertain accounting creates only a sealed reference to the
            // retained owner, never a fresh lifecycle record or native grant.
            retain_same_uncertain_owner(&inner);
        }
        Self {
            inner,
            lifecycle_record,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardedRetirementState {
    Active,
    Terminal,
    Closed,
}

/// Refusal to physically retire the actual standalone guarded Main factory.
#[derive(Debug, thiserror::Error)]
pub enum GuardedCampaignOwnerRetirementError {
    /// Another strong or weak facade still retains this same owner.
    #[error("guarded Main owner borrowers remain")]
    SharedOwner,
    /// This facade's final-release accounting is uncertain and retained.
    #[error("guarded Main final-release custody is uncertain and retained")]
    UncertainOwner,
    /// This facade borrows a packaged Main that has a separate whole-owner path.
    #[error("guarded facade cannot retire its containing packaged Main")]
    BorrowedMain,
    /// The original actor cannot atomically close quiescent admission.
    #[error("guarded Main actor retirement refused: {0}")]
    Actor(#[source] HostOperationalError),
    /// The same Main worker or queued lifecycle body remains retained.
    #[error("guarded Main controls retirement refused: {0}")]
    Controls(#[source] crate::campaign_process::ExecutorControlRetirementError),
    /// The same concrete native factory retains physical or uncertain custody.
    #[error("guarded Main native factory retirement refused: {0}")]
    Factory(#[source] QemuVmRealizationError),
    /// The same Main queue still retains physical or uncertain lifecycle custody.
    #[error("guarded Main lifecycle cleanup refused: {0}")]
    LifecycleCleanup(#[source] crucible_api::LifecycleApiError),
}

impl GuardedCampaignOwner {
    pub(crate) fn physically_retired(&self) -> bool {
        self.inner.retirement == GuardedRetirementState::Closed
    }

    /// Retires this actual standalone owner's native factory at its terminal boundary.
    ///
    /// Clone drops and campaign completion leave Main live. This borrowed
    /// operation requires the exact exclusive standalone owner, closes its
    /// original admission route atomically, and then closes the actual native
    /// roster and paid persistent Target dispatcher. Storage and actor charges
    /// remain owned until their separate physical holders end.
    ///
    /// # Errors
    /// Refuses borrowed packaged authority, owner or factory aliases, active or
    /// queued execution, native node reservations, and physical retirement
    /// uncertainty. The complete same owner remains available on every error;
    /// once its actor enters terminal state, new admission stays closed while
    /// old physical cleanup and retirement retry can continue.
    pub fn try_retire(&mut self) -> Result<(), GuardedCampaignOwnerRetirementError> {
        if !self.lifecycle_record || self.inner.facades.is_quarantined() {
            return Err(GuardedCampaignOwnerRetirementError::UncertainOwner);
        }
        let controls = self.inner.config.normal_executor.as_ref().and_then(|main| {
            crate::campaign_process::try_retire_executor_controls_for_main(main).err()
        });
        let lifecycle = self.inner.lifecycle_cleanup.as_ref().and_then(|queue| {
            let work = queue.retry_pending();
            let empty = queue.verify_empty();
            work.and(empty).err()
        });
        let controls = match controls {
            Some(error) if !error.physically_closed() => {
                return Err(GuardedCampaignOwnerRetirementError::Controls(error));
            }
            other => other,
        };
        if let Some(error) = lifecycle {
            return Err(GuardedCampaignOwnerRetirementError::LifecycleCleanup(error));
        }
        let owner = Arc::get_mut(&mut self.inner)
            .ok_or(GuardedCampaignOwnerRetirementError::SharedOwner)?;
        let preparation = owner
            ._preparation
            .as_mut()
            .ok_or(GuardedCampaignOwnerRetirementError::BorrowedMain)?;
        if owner.retirement == GuardedRetirementState::Closed {
            return controls.map_or(Ok(()), |error| {
                Err(GuardedCampaignOwnerRetirementError::Controls(error))
            });
        }
        let factory = owner
            .host
            .exclusive_factory()
            .map_err(GuardedCampaignOwnerRetirementError::Factory)?;
        factory
            .verify_native_quiescent()
            .map_err(GuardedCampaignOwnerRetirementError::Factory)?;
        if owner.retirement == GuardedRetirementState::Active {
            preparation
                .try_begin_terminal()
                .map_err(GuardedCampaignOwnerRetirementError::Actor)?;
            owner.retirement = GuardedRetirementState::Terminal;
        }
        factory
            .finish_target_dispatcher()
            .map_err(GuardedCampaignOwnerRetirementError::Factory)?;
        owner.retirement = GuardedRetirementState::Closed;
        match controls {
            Some(error) => Err(GuardedCampaignOwnerRetirementError::Controls(error)),
            None => Ok(()),
        }
    }
}

impl Drop for GuardedCampaignOwner {
    fn drop(&mut self) {
        if !self.lifecycle_record {
            return;
        }
        #[cfg(test)]
        if let Some(barrier) = &self.inner.facades.release_barrier {
            barrier.wait();
        }
        match self.inner.facades.release() {
            Ok(false) => return,
            Err(()) => {
                retain_same_uncertain_owner(&self.inner);
                return;
            }
            Ok(true) => {}
        }
        if self.inner._preparation.is_none() {
            return;
        }
        // Exactly one actual facade release selects this terminal attempt.
        // Arc/actor/roster gates independently prove physical closure. Another
        // releasing facade may still hold the header: retain the same body on
        // that refusal rather than claiming guaranteed concurrent retirement.
        if self.try_retire().is_err() && !self.physically_retired() {
            retain_same_uncertain_owner(&self.inner);
        }
    }
}

#[cfg(test)]
impl GuardedCampaignOwner {
    pub(crate) fn install_final_release_barrier(
        &mut self,
        barrier: Arc<std::sync::Barrier>,
    ) -> Result<(), GuardedCampaignOwnerRetirementError> {
        let owner = Arc::get_mut(&mut self.inner)
            .ok_or(GuardedCampaignOwnerRetirementError::SharedOwner)?;
        owner.facades.release_barrier = Some(barrier);
        Ok(())
    }

    pub(crate) fn corrupt_final_release_record_for_test(&self) {
        self.inner.facades.records.store(0, Ordering::Release);
    }

    pub(crate) fn exhaust_final_clone_record_for_test(&self) {
        self.inner
            .facades
            .records
            .store(usize::MAX, Ordering::Release);
    }
}
