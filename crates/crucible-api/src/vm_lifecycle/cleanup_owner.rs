//! Moves existing lifecycle custody into a pre-reserved service cleanup cell.
//!
//! A reservation occupies an exact cell before launch effects. Its queue link
//! is weak, including when another retained Target can reach this Source. The
//! containing Main service owns and drains the queue. It retries saved owners;
//! neither a handoff nor an unsuccessful retry certifies physical return.

use super::{
    ProductionVmHotForkSourceWorld, ProductionVmLifecycleLoop, ProductionVmNodeLauncher,
    SchedulerError,
};
use crate::LifecycleApiError;
use crucible::QuantumLoop as _;

/// Retains the existing owner at the point where construction or cleanup stopped.
///
/// The Source variant includes its prepared templates, disk custody, captured
/// continuation and cleanup observer. It does not detach those obligations from
/// the lifecycle merely to retain its launcher.
#[must_use = "retry cleanup or transfer the unchanged owner into its reserved cell"]
pub enum ProductionVmCleanupOwner {
    /// Retains a launcher's partial effects before a complete lifecycle exists.
    Launcher(Box<dyn ProductionVmNodeLauncher>),
    /// Retains a complete lifecycle, including its actual launcher and backend.
    Lifecycle(Box<ProductionVmLifecycleLoop>),
    /// Retains a complete prepared Source and its host continuation.
    SourceWorld(ProductionVmHotForkSourceWorld),
    /// Retains the same carrier allocated before Source construction effects.
    Construction(Box<super::ProductionVmConstructionCustody>),
}

impl ProductionVmCleanupOwner {
    /// Retries cleanup through this same owner's existing shutdown route.
    ///
    /// # Errors
    /// Preserves the complete owner when its physical or semantic shutdown
    /// refuses. No replacement Original, permit, epoch or authority is supplied.
    pub fn retry_cleanup(&mut self) -> Result<(), SchedulerError> {
        match self {
            Self::Launcher(launcher) => launcher.finish().map_err(cleanup_error),
            Self::Lifecycle(lifecycle) => lifecycle.shutdown().map(|_| ()),
            Self::SourceWorld(source) => source.retire().map_err(cleanup_error),
            Self::Construction(custody) => {
                custody
                    .retry_cleanup()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: error.to_string(),
                    })
            }
        }
    }
}

/// Occupies one authenticated cleanup cell before lifecycle effects begin.
///
/// Implementations reserve capacity and retain its exact epoch before this
/// object is constructed. They never search for capacity during handoff. Every
/// reservation links weakly to its queue: a Target can also retain a parent
/// Source, so taking only the Target reservation would not break a strong cycle.
/// The containing Main service drains this queue before retiring its owner.
/// Dropping a reservation alone must not release an uncertain cell.
pub trait ProductionVmCleanupReservation: Send {
    /// Transfers the actual owner into this reservation's already occupied cell.
    ///
    /// Success returns this same preallocated token as an exact-cell handoff
    /// driver; it allocates neither another token nor an owner. The caller
    /// retains it until physical completion, then drops it before another birth.
    /// This consumes the reservation separately from the owner. The stored
    /// owner must contain no strong reservation edge back to the queue.
    ///
    /// # Errors
    /// Returns the same reservation and owner when the queue no longer exists
    /// or its exact epoch cannot be authenticated. The caller retains both for
    /// the same retry; refusal certifies neither cleanup nor a reusable cell.
    fn retain(
        self: Box<Self>,
        owner: ProductionVmCleanupOwner,
    ) -> Result<
        Box<dyn ProductionVmCleanupHandoff>,
        (
            Box<dyn ProductionVmCleanupReservation>,
            ProductionVmCleanupOwner,
        ),
    >;

    /// Releases an unused reservation after successful cleanup and owner drop.
    ///
    /// The caller destroys the actual owner, including its factory aliases,
    /// outside the queue mutex before invoking this method. Queued cleanup
    /// performs the same ordering while its cell remains in progress.
    ///
    /// # Errors
    /// Refuses stale, poisoned or otherwise uncertain reservation state without
    /// making that cell available to another lifecycle.
    fn complete(self: Box<Self>) -> Result<(), LifecycleApiError>;
}

/// Reports physical facts about one actual cleanup cell and epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionVmCleanupStage {
    /// The complete containing body remains owned or destruction is uncertain.
    BodyRetained,
    /// The actual body was destroyed, but its containing-body lease remains open.
    BodyDestroyed,
    /// Actual destruction and closure of its containing-body lease completed.
    ///
    /// Aggregate World resources remain owned until their independent native
    /// members and aggregate owner close. This is not an aggregate refund.
    Complete,
}

/// Drives only the exact cell that received an already allocated owner.
///
/// Publication alone is not physical cleanup. The same token Box is retained
/// throughout; no new Original, queue selection or allocation is supplied.
pub trait ProductionVmCleanupHandoff: Send {
    /// Performs one bounded cleanup attempt on this exact cell and epoch.
    ///
    /// # Errors
    /// Refuses a missing containing Main, stale cell, saved-owner cleanup,
    /// destruction uncertainty or containing charge return. The same driver
    /// remains usable; an error does not identify the physical stage.
    fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;

    /// Observes and latches this cell's physical stage without running cleanup.
    ///
    /// Observing complete closure transfers its first cleanup cause into this
    /// same token before the cell can be reused. A completed receipt remains
    /// factual across later epochs and never drives their owners.
    ///
    /// # Errors
    /// Refuses unavailable or inconsistent custody without claiming closure.
    fn stage(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;

    /// Borrows the first cleanup cause transferred at physical completion.
    ///
    /// Earlier refusal remains in the exact cell until completion is observed.
    /// This historical cause does not change a factual `Complete` stage.
    fn first_failure(&self) -> Option<&SchedulerError>;

    /// Moves the actual first cleanup cause from this completed receipt.
    ///
    /// Returns `None` until physical completion has transferred the cause from
    /// its exact cell, or after the same cause has already been taken. Moving
    /// history neither renews cleanup nor changes the completed physical fact.
    fn take_first_failure(&mut self) -> Option<SchedulerError>;
}

fn cleanup_error(error: LifecycleApiError) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: error.to_string(),
    }
}
