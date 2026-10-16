//! Transfers existing backend owners through prepaid cleanup cells.
//!
//! This module defines operations and physical observations only. The backend
//! owns its concrete partial frame, assembly, and completed execution body.
//! A handoff consumes the already allocated owner; it does not allocate one.

use crate::LifecycleApiError;

/// Retains an existing backend body while retrying its physical cleanup.
///
/// Implementations keep their actual partial or complete resources together.
/// Success permits destruction of that same body outside the queue lock; it
/// does not return the containing charge until destruction itself completes.
pub trait ProductionVmCleanupOwner: Send {
    /// Failure retained in the receiving owner's existing cleanup history.
    type Failure: std::error::Error + Send + 'static;

    /// Retries cleanup through this same owner's existing saved authority.
    ///
    /// # Errors
    /// Preserves the complete owner on physical refusal or uncertain custody.
    /// This operation admits no replacement Original, permit, epoch, or budget.
    fn retry_cleanup(&mut self) -> Result<(), Self::Failure>;
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
    /// Failure retained in the receiving owner's existing cleanup history.
    type Failure: std::error::Error + Send + 'static;

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
        owner: Box<dyn ProductionVmCleanupOwner<Failure = Self::Failure>>,
    ) -> Result<
        Box<dyn ProductionVmCleanupHandoff<Failure = Self::Failure>>,
        (
            Box<dyn ProductionVmCleanupReservation<Failure = Self::Failure>>,
            Box<dyn ProductionVmCleanupOwner<Failure = Self::Failure>>,
        ),
    >;
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
    /// Failure retained in the receiving owner's existing cleanup history.
    type Failure: std::error::Error + Send + 'static;

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
    fn first_failure(&self) -> Option<&Self::Failure>;

    /// Moves the actual first cleanup cause from this completed receipt.
    ///
    /// Returns `None` until physical completion has transferred the cause from
    /// its exact cell, or after the same cause has already been taken. Moving
    /// history neither renews cleanup nor changes the completed physical fact.
    fn take_first_failure(&mut self) -> Option<Self::Failure>;
}
