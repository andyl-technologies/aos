//! Retains the once-only executor constructor in the authentic permanent Main.
//!
//! This inline cell is part of `ProcessActor`'s before-birth structural debit.
//! Publication moves the existing whole owner and does no Cleanup. Retry uses
//! only that same Main's lazily retained Cleanup and the owner's existing route.

use super::{ACTOR, CampaignProcessOwner};
use crate::packaged_qemu_executor::{PackagedQemuExecutor, guarded::GuardedCampaignOwner};
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedNativeSlotPurpose, ServiceBirthError,
};
use crucible_host_resources::host_supervision::HostSupervisionError;
use std::sync::Arc;

/// Retains the two constructors or their one subsequent active Attached body.
pub(crate) enum RetainedExecutorConstruction {
    Packaged(PackagedQemuExecutor),
    Guarded(GuardedCampaignOwner),
    Attached(crate::packaged_qemu_executor::RetainedAttachedRetirement),
}

/// Returns the same constructor when its exact Main cell cannot accept custody.
///
/// This type deliberately owns the body; a custody rejection is never converted
/// to a diagnostic that silently destroys a still-born executor.
#[must_use = "retain the same constructor in its authentic Main before discarding the failure"]
pub struct ExecutorConstructionCustodyFailure {
    owner: std::sync::Mutex<Option<RetainedExecutorConstruction>>,
    source: ServiceBirthError,
    reason: &'static str,
}

impl std::fmt::Debug for ExecutorConstructionCustodyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutorConstructionCustodyFailure")
            .field("source", &self.source)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ExecutorConstructionCustodyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; same constructor retained by returned failure: {}",
            self.source, self.reason
        )
    }
}

impl std::error::Error for ExecutorConstructionCustodyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl ExecutorConstructionCustodyFailure {
    /// Repeats custody publication without allocating, starting Cleanup or renewal.
    ///
    /// # Errors
    /// Returns the same complete failure if the exact Main remains unavailable,
    /// occupied or poisoned. No owner is destroyed on this refusal path.
    pub fn retry_retention(
        mut self,
        main: &Arc<AuthenticatedNativeSlotPurpose>,
    ) -> Result<&'static ServiceBirthError, Self> {
        let Ok(slot) = self.owner.get_mut() else {
            return Err(self);
        };
        let Some(owner) = slot.take() else {
            return Err(self);
        };
        retain_executor_construction(main, owner, self.source)
    }
}

pub(crate) fn retain_executor_construction(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    owner: RetainedExecutorConstruction,
    source: ServiceBirthError,
) -> Result<&'static ServiceBirthError, ExecutorConstructionCustodyFailure> {
    let reject = |owner, source, reason| ExecutorConstructionCustodyFailure {
        owner: std::sync::Mutex::new(Some(owner)),
        source,
        reason,
    };
    let Some(actor) = ACTOR.get() else {
        return Err(reject(owner, source, "permanent Main is unpublished"));
    };
    if !actor
        .executor
        .get()
        .is_some_and(|admitted| Arc::ptr_eq(admitted, main))
    {
        return Err(reject(owner, source, "constructor belongs to another Main"));
    }
    // Expiry can refuse execution, but cannot revoke this already-born custody.
    let Ok(mut slot) = actor.construction.try_lock() else {
        return Err(reject(
            owner,
            source,
            "Main constructor cell is occupied or poisoned",
        ));
    };
    if slot.is_some() || actor.construction_first.get().is_some() {
        return Err(reject(
            owner,
            source,
            "once-only Main constructor is already retained",
        ));
    }
    // The cell is exclusive and the first-cause slot was empty. Its initializer
    // only moves the already-born error; it invokes no user callback.
    let first = actor.construction_first.get_or_init(|| source);
    *slot = Some(owner);
    Ok(first)
}

/// Retains the initiating constructor failure and independent cleanup evidence.
#[derive(Debug, thiserror::Error)]
pub enum RetainedExecutorRetirementError {
    /// The same active attached body's first report or physical refusal remains.
    #[error("attached executor retirement: {0}")]
    Attached(#[source] crate::packaged_qemu_executor::PackagedQemuExecutorJoinError),
    /// The authentic permanent Main or exact retained constructor is unavailable.
    #[error("retained executor custody is unavailable: {0}")]
    Custody(&'static str),
    /// The same Main could not enter its once-only saved Cleanup.
    #[error("retained executor Cleanup admission refused: {0}")]
    Admission(#[source] ServiceBirthError),
    /// Cleanup retained a cause, independently of the body's physical closure.
    #[error(
        "retained executor constructor first failed: {first}; cleanup: {cause:?}; Main controls: {controls:?}; independent post: {post:?}"
    )]
    Cleanup {
        /// The initiating constructor cause retained by the permanent actor.
        first: &'static ServiceBirthError,
        /// The actual same-owner retirement refusal.
        #[source]
        cause: Option<RetainedExecutorCleanupError>,
        /// Independent worker and lifecycle-queue refusal after the owner step.
        controls: Option<super::ExecutorControlRetirementError>,
        /// The independently observed same Original postcut.
        post: Option<HostSupervisionError>,
    },
    /// The real owner was destroyed, but its independent Original post refused.
    #[error("retained executor physically destroyed after {first}; independent post: {post}")]
    Post {
        /// The immutable initiating constructor failure.
        first: &'static ServiceBirthError,
        /// The actual postcut; physical destruction does not erase this refusal.
        #[source]
        post: HostSupervisionError,
    },
}

/// Reports the existing physical cleanup route without replacing its cause.
#[derive(Debug, thiserror::Error)]
pub enum RetainedExecutorCleanupError {
    /// The exact body belongs to the distinct active Attached route.
    #[error("attached body requires its same Main retirement route")]
    Custody,
    /// The authentic saved Main interval refused before effects.
    #[error(transparent)]
    Original(#[from] HostSupervisionError),
    /// The unserved packaged executor retained a real worker or native owner.
    #[error(transparent)]
    Packaged(
        #[from] crate::packaged_qemu_executor::original_retirement::OriginalPackagedRetirementError,
    ),
    /// The standalone guarded owner retained aliases or native state.
    #[error(transparent)]
    Guarded(#[from] crate::GuardedCampaignOwnerRetirementError),
}

impl CampaignProcessOwner {
    /// Retries the actual retained constructor through its same saved Cleanup.
    ///
    /// The inline owner stays in the cell across every refused callback. After
    /// successful physical cleanup its body is destroyed outside the mutex;
    /// the initiating error remains observable and never becomes success.
    ///
    /// # Errors
    /// Refuses absent/occupied custody, unavailable same Main Cleanup, unfinished
    /// actual cleanup, or its independent postcut. No replacement guard is used.
    pub fn retry_retained_executor_construction(
        &self,
    ) -> Result<(), RetainedExecutorRetirementError> {
        let actor = ACTOR.get().ok_or(RetainedExecutorRetirementError::Custody(
            "Main is unpublished",
        ))?;
        let main = actor
            .executor
            .get()
            .ok_or(RetainedExecutorRetirementError::Custody(
                "Main executor is unpublished",
            ))?;
        let mut slot = actor.construction.try_lock().map_err(|_| {
            RetainedExecutorRetirementError::Custody("constructor cell is occupied or poisoned")
        })?;
        let Some(owner) = slot.as_mut() else {
            return Ok(());
        };
        if matches!(owner, RetainedExecutorConstruction::Attached(_)) {
            drop(slot);
            return super::retry_attached_retirement(main)
                .map_err(RetainedExecutorRetirementError::Attached);
        }
        let first =
            actor
                .construction_first
                .get()
                .ok_or(RetainedExecutorRetirementError::Custody(
                    "constructor first cause is absent",
                ))?;
        let original = main
            .retained_cleanup()
            .map_err(RetainedExecutorRetirementError::Admission)?;
        let work = (|| {
            original.wait_slice()?;
            match owner {
                RetainedExecutorConstruction::Packaged(owner) => owner
                    .try_retire_original(&original)
                    .map_err(RetainedExecutorCleanupError::from),
                RetainedExecutorConstruction::Guarded(owner) => owner
                    .try_retire()
                    .map_err(RetainedExecutorCleanupError::from),
                RetainedExecutorConstruction::Attached(_) => {
                    Err(RetainedExecutorCleanupError::Custody)
                }
            }
        })();
        // A failed pool route may have published a lifecycle body while
        // retaining its worker. Always revisit both before deciding ownership.
        let controls = super::try_retire_executor_controls(main, &original).err();
        let post = original.wait_slice().err();
        finish_retained_construction(
            slot,
            |owner| match owner {
                RetainedExecutorConstruction::Packaged(owner) => owner.physically_retired(),
                RetainedExecutorConstruction::Guarded(owner) => owner.physically_retired(),
                RetainedExecutorConstruction::Attached(_) => false,
            },
            first,
            work.err(),
            controls,
            post,
        )
    }
}

/// Destroys an actually closed body before reporting its independent history.
///
/// The private production caller supplies only the retained owner's observation.
/// A failed Original post cannot reverse physical closure or require another
/// cleanup attempt on resources that have already returned.
fn finish_retained_construction<T>(
    mut slot: std::sync::MutexGuard<'_, Option<T>>,
    owner_closed: impl FnOnce(&T) -> bool,
    first: &'static ServiceBirthError,
    cause: Option<RetainedExecutorCleanupError>,
    controls: Option<super::ExecutorControlRetirementError>,
    post: Option<HostSupervisionError>,
) -> Result<(), RetainedExecutorRetirementError> {
    let physically_closed = slot.as_ref().is_some_and(owner_closed)
        && controls
            .as_ref()
            .is_none_or(|error| error.physically_closed());
    if !physically_closed {
        return Err(RetainedExecutorRetirementError::Cleanup {
            first,
            cause,
            controls,
            post,
        });
    }

    let returned = slot.take();
    drop(slot);
    // Destruction follows actual member closure and runs outside the cell lock.
    // Historical reports cannot require another attempt before releasing this body.
    drop(returned);
    if cause.is_some() || controls.is_some() {
        return Err(RetainedExecutorRetirementError::Cleanup {
            first,
            cause,
            controls,
            post,
        });
    }
    match post {
        Some(post) => Err(RetainedExecutorRetirementError::Post { first, post }),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "retained_construction/tests.rs"]
mod tests;
